import os
import yaml
import stripe
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel

# Read stripe keys from environment variables
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
# Basic plan for $99/mo (example)
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "price_test_12345")

billing_router = APIRouter(prefix="/billing", tags=["Billing"])

def get_profile_path(client_id: str) -> Path:
    return Path(f"knowledge/client_profiles/{client_id}.yaml")

def load_profile(client_id: str) -> dict:
    profile_path = get_profile_path(client_id)
    if not profile_path.is_file():
        raise HTTPException(status_code=404, detail="Client profile not found")
    with open(profile_path, "r") as f:
        return yaml.safe_load(f) or {}

def save_profile(client_id: str, profile_data: dict):
    profile_path = get_profile_path(client_id)
    with open(profile_path, "w") as f:
        yaml.safe_dump(profile_data, f, default_flow_style=False)

class CheckoutRequest(BaseModel):
    client_id: str
    success_url: str
    cancel_url: str

@billing_router.post("/create-checkout-session")
async def create_checkout_session(req: CheckoutRequest):
    """Create a Stripe checkout session for the client to subscribe."""
    if not stripe.api_key:
        raise HTTPException(status_code=500, detail="Stripe API key not configured")
    
    profile = load_profile(req.client_id)
    
    # Check if they already have an active subscription
    if profile.get("subscription_status") == "active":
        raise HTTPException(status_code=400, detail="Client already has an active subscription")

    try:
        customer_id = profile.get("stripe_customer_id")
        if not customer_id:
            # Create a new stripe customer
            customer = stripe.Customer.create(
                email=profile.get("email", f"{req.client_id}@example.com"),
                metadata={"client_id": req.client_id}
            )
            customer_id = customer.id
            profile["stripe_customer_id"] = customer_id
            save_profile(req.client_id, profile)

        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=[{
                "price": STRIPE_PRICE_ID,
                "quantity": 1,
            }],
            mode="subscription",
            success_url=req.success_url + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=req.cancel_url,
            client_reference_id=req.client_id,
        )
        return {"checkout_url": checkout_session.url}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@billing_router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe Webhooks for subscription lifecycle events."""
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")
        
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        client_id = session.get("client_reference_id")
        if client_id:
            profile = load_profile(client_id)
            profile["stripe_subscription_id"] = session.get("subscription")
            profile["subscription_status"] = "active"
            save_profile(client_id, profile)
            
    # Handle subscription updates (e.g., cancellation or payment failure)
    elif event['type'] == 'customer.subscription.updated' or event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get("customer")
        status = subscription.get("status")
        
        # We need to find the client_id by customer_id
        # Since we use YAML files, we have to iterate through them
        profiles_dir = Path("knowledge/client_profiles")
        for file in profiles_dir.glob("*.yaml"):
            with open(file, "r") as f:
                profile = yaml.safe_load(f)
                if profile and profile.get("stripe_customer_id") == customer_id:
                    profile["subscription_status"] = status
                    with open(file, "w") as fw:
                        yaml.safe_dump(profile, fw, default_flow_style=False)
                    break

    return {"status": "success"}

@billing_router.post("/portal")
async def create_portal_session(client_id: str, return_url: str):
    """Create a link to the Stripe Customer Portal for managing subscriptions."""
    profile = load_profile(client_id)
    customer_id = profile.get("stripe_customer_id")
    
    if not customer_id:
        raise HTTPException(status_code=400, detail="No billing account found for this client")
        
    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return {"portal_url": portal_session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
