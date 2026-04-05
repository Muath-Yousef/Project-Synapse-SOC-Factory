#!/bin/bash
PROJECT_DIR="/media/kyrie/VMs1/Cybersecurity_Tools_Automation"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python3"
SCHEDULER="$PROJECT_DIR/scheduler.py"
LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$LOG_DIR"
WEEKLY_CRON="0 6 * * 1 cd $PROJECT_DIR && $VENV_PYTHON $SCHEDULER --mode weekly >> $LOG_DIR/scheduler_weekly.log 2>&1"
MONTHLY_CRON="0 8 1 * * cd $PROJECT_DIR && $VENV_PYTHON $SCHEDULER --mode monthly >> $LOG_DIR/scheduler_monthly.log 2>&1"
(crontab -l 2>/dev/null | grep -v "synapse_scheduler"; \
 echo "# synapse_scheduler_weekly"; echo "$WEEKLY_CRON"; \
 echo "# synapse_scheduler_monthly"; echo "$MONTHLY_CRON") | crontab -
echo "✅ Cron jobs installed:"
echo "   Weekly:  Every Monday 06:00"
echo "   Monthly: 1st of month 08:00"
crontab -l | grep synapse
