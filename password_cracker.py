import hashlib

def crack_sha1_hash(hash, use_salts=False):
  with open("top-10000-passwords.txt", "r") as file:
    if not use_salts:
      # Iterate through passwords, hash each one and compare it to the given hash
      for cracked_password1 in file:
        hashed_Password = hashlib.sha1(cracked_password1.strip().encode('utf-8')).hexdigest()
        if hashed_Password == hash:
          return cracked_password1.strip()
    else:
      with open('known-salts.txt', 'r') as salt_file:
        for salt in salt_file:
          file.seek(0)
          for cracked_password2 in file:
            # appended & prepended salt to password, hash them and compare it to the given hash
            prepend_salted = (salt.strip() + cracked_password2.strip())
            append_salted = (cracked_password2.strip() + salt.strip())
            hash_to_compare1 = hashlib.sha1(prepend_salted.encode('utf-8')).hexdigest()
            hash_to_compare2 = hashlib.sha1(append_salted.encode('utf-8')).hexdigest()
            if hash_to_compare1 == hash or hash_to_compare2 == hash:
              return cracked_password2.strip()

  # if there is no match
  return "PASSWORD NOT IN DATABASE"