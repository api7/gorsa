# example

An example that crypt message with a private key

## generate key
```shell
openssl genrsa  -out private.key 2048

openssl req -new -x509 -days 365 -key private.key -out public.crt
```

## crypt message with private key

```shell
go run example.go -key /path/to/private.key -msg "test"
```

## decrypt data with public cert

```shell
go run example.go -cert /path/to/public.crt -data "V7syU9s3MOgQR6b16737ypr64eHZU0RyCruPwXbGvOIW4DLrdaG2qhl1XmKqVdB_00h31AmDNICb-fot-F10N7M00RNNeUfvzZD3n5I1qKcFpbFJfqbb0JTonphvOB6k645sLJd2GXqwifR5rHzDehl0Fqux0z8zFBY8EWmFRFtiTzp7URk9rXktEPPWPGY5ncHB50vpNZTvcyuHVb2CmTxhrGvdWWVMubn0cB9a8Yr5vdHCgufx8MWCm-p6tAXL_S6BwdtKE4DfPF443yVhMhlJT2IZXLga4qVM28Cwy8FrGmCXU9mPgsUR6F2Q6TV5AYSqnSKy8I40UE9Nid03jw"
```
