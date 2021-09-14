build:
	rm -f assets/*
	cd lambda && zip ../assets/scp-s3-event-dispatcher.zip scp-s3-event-dispatcher.py
	cd lambda && zip ../assets/scp-iam-event-dispatcher.zip scp-iam-event-dispatcher.py
	cd lambda && zip ../assets/scp-account-register.zip scp-account-register.py
	cp -f cloudformation/scp-service-catalog-product-template.yaml assets/scp-service-catalog-product-template.yaml
