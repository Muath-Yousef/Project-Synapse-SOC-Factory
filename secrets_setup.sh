#!/bin/bash
set -e

echo "🔒 بدء تهيئة نظام إدارة الأسرار (SOPS + Age) لـ SOC Root..."

# تحديد مسار التثبيت المحلي لتجنب الحاجة لصلاحيات Root دائمًا
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

# 1. التحقق من تثبيت age وتثبيته إن لم يوجد
if ! command -v age &> /dev/null; then
    echo "⚙️ جاري تثبيت age..."
    curl -sLo age.tar.gz "https://github.com/FiloSottile/age/releases/download/v1.1.1/age-v1.1.1-linux-amd64.tar.gz"
    tar -xzf age.tar.gz
    mv age/age age/age-keygen "$LOCAL_BIN/"
    rm -rf age age.tar.gz
    echo "✅ تم تثبيت age."
else
    echo "✅ أداة age مثبتة مسبقاً."
fi

# 2. التحقق من تثبيت sops وتثبيته إن لم يوجد
if ! command -v sops &> /dev/null; then
    echo "⚙️ جاري تثبيت sops..."
    curl -sLo sops "https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64"
    chmod +x sops
    mv sops "$LOCAL_BIN/"
    echo "✅ تم تثبيت sops."
else
    echo "✅ أداة sops مثبتة مسبقاً."
fi

# 3. إنشاء مفاتيح التشفير
AGE_DIR="$HOME/.config/sops/age"
KEY_FILE="$AGE_DIR/keys.txt"

if [ ! -f "$KEY_FILE" ]; then
    echo "🔑 جاري توليد مفتاح تشفير Age جديد..."
    mkdir -p "$AGE_DIR"
    age-keygen -o "$KEY_FILE"
    echo "✅ تم توليد المفتاح وحفظه في: $KEY_FILE"
else
    echo "✅ مفتاح Age موجود بالفعل."
fi

# استخراج المفتاح العام (Public Key)
PUB_KEY=$(grep "public key:" "$KEY_FILE" | awk '{print $4}')

# 4. إعداد ملف .sops.yaml للمستودع
cat > .sops.yaml <<EOF
creation_rules:
  - path_regex: \.env$
    age: '$PUB_KEY'
EOF
echo "✅ تم إنشاء إعدادات .sops.yaml للمستودع."

# 5. إنشاء قالب .env للتجربة
if [ ! -f ".env" ] && [ ! -f ".env.enc" ]; then
    cat > .env <<EOF
# قالب الأسرار لـ SOC Root
GEMINI_API_KEY="your_api_key_here"
CLOUDFLARE_API_TOKEN="your_token_here"
EOF
    echo "✅ تم إنشاء ملف .env أولي. سيتم تشفيره الآن..."
    sops -e .env > .env.enc
    rm .env
    echo "✅ تم تشفير الأسرار بنجاح إلى .env.enc وحذف الملف الأصلي."
fi

echo "🎉 اكتمل إعداد نظام الأسرار!"
echo "💡 لفك التشفير لاحقاً، استخدم الأمر: sops -d .env.enc > .env"
