Must generate private key with the below command
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

extract with the command
openssl rsa -pubout -in private.pem -out public.pem


After generate must store in the resource with its name