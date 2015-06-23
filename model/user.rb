require 'protected_attributes'
require 'sinatra/activerecord'
require 'rbnacl/libsodium'
require 'base64'
require_relative '../environments'

class User < ActiveRecord::Base
  validates :username, presence: true, uniqueness: true
  validates :email, presence: true, format: /@/
  validates :user_password, presence: true
 # validates :full_name, presence: true
 # validates :address, presence: true
  #validates :dob, presence: true

attr_accessible :username, :email

def key
  Base64.urlsafe_decode64(ENV['DB_KEY'])
  #ENV['DB_KEY'].dup.force_encoding Encoding::BINARY
end

def field_encrypt(val,field)
  box_closed = RbNaCl::SecretBox.new(key)
  nonce = RbNaCl::Random.random_bytes(box_closed.nonce_bytes)
  encrypted_val = box_closed.encrypt(nonce,val)

  #encoded using base64 to eliminate encoding issues
  case field
    when :full_name
      self.nonce_full_name = Base64.urlsafe_encode64(nonce)
      self.full_name = Base64.urlsafe_encode64(encrypted_val)
    when :address
      self.nonce_address = Base64.urlsafe_encode64(nonce)
      self.address = Base64.urlsafe_encode64(encrypted_val)
    when :dob
      self.nonce_dob = Base64.urlsafe_encode64(nonce)
      self.dob = Base64.urlsafe_encode64(encrypted_val)
  end
end

def field_decrypt(field)
  box_open = RbNaCl::SecretBox.new(key)
  #decoded using base64 to eliminate encoding issues
  case field
    when :full_name
      nonce = Base64.urlsafe_decode64(self.nonce_full_name)
      encrypt_val = Base64.urlsafe_decode64(self.full_name)
      box_open.decrypt(nonce, encrypt_val)
    when :address
      nonce = Base64.urlsafe_decode64(self.nonce_address)
      encrypt_val = Base64.urlsafe_decode64(self.address)
      box_open.decrypt(nonce, encrypt_val)
    when :dob
      nonce = Base64.urlsafe_decode64(self.nonce_dob)
      encrypt_val = Base64.urlsafe_decode64(self.dob)
      box_open.decrypt(nonce, encrypt_val)
  end

end

#authentication methods
def password=(new_password)
salt = RbNaCl::Random.random_bytes(RbNaCl::PasswordHash::SCrypt::SALTBYTES)
digest = self.class.hash_password(salt, new_password)
self.salt = Base64.urlsafe_encode64(salt)
self.user_password = Base64.urlsafe_encode64(digest)
end

def self.hash_password(salt, pwd)
opslimit = 2**20
memlimit = 2**24
digest_size = 64
RbNaCl::PasswordHash.scrypt(pwd, salt, opslimit, memlimit, digest_size)
end

def password_matches?(try_password)
salt = Base64.urlsafe_decode64(self.salt)
attempted_password = self.class.hash_password(salt,try_password)
self.user_password == Base64.urlsafe_encode64(attempted_password)
end

def self.authenticate!(username, login_password)
user = User.find_by_username(username)
user && user.password_matches?(login_password) ? user : nil
end


end
