# netbox-autodiscovery


## Copy env template to .env
```
cp env-template .env
```

Add your url and token to .env

NETBOX_URL=https://your-netbox-instance/api/ipam/ip-addresses/
NETBOX_TOKEN=YOUR_NETBOX_API_TOKEN

## Install requirements
python -m pip install -r requirements.txt

## Add subnet to scan
```
# Add subnet to scan
ip_subnet = "192.168.1.0/24"
```