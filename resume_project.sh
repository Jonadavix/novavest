#!/data/data/com.termux/files/usr/bin/bash

cd ~/investment_site || exit 1

if [ ! -d "venv" ]; then
    echo "ERROR: venv not found."
    exit 1
fi

source venv/bin/activate

echo ""
echo "======================================"
echo " Investment Platform"
echo "======================================"
echo "Project: ~/investment_site"
echo "Python:  $(python --version)"
echo ""
echo "Next task:"
echo "Test controlled ₦100 CREDIT adjustment"
echo ""
echo "Jonathan current balance should be:"
echo "₦70,200.00"
echo ""
echo "Start Flask with:"
echo "python app.py"
echo ""
echo "Then open:"
echo "http://127.0.0.1:5000/admin/balance-adjustments"
echo "======================================"
