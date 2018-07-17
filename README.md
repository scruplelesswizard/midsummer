

Process:

check request file hash matches known request

for each primaryKey
  generate Key
  self-sign
  *cross-sign*
  request yubikey
  write card data to yubikey
  write private keys to yubikey
  write public key and stubs to public usb drive
  [write backup to usb drive]
  write revocation certificate to revocation usb drive
end
