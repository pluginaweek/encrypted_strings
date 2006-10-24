require 'sentry'

desc "Creates a private/public key for asymmetric encryption:  rake sentry_key PUB=/path/to/public.key PRIV=/path/to/priv.key [KEY=secret]"
task :encryption_key do
  Sentry::AsymmetricSentry.save_random_rsa_key(
    ENV['PRIV'] || 'private.key', 
    ENV['PUB']  || 'public.key', 
    :key => ENV['KEY'])
end