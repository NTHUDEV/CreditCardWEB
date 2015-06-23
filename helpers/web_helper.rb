require 'jwt'
require 'pony'
require 'sendgrid-ruby'
require 'base64'
require 'rbnacl/libsodium'
require_relative 'email_helper'
require 'httparty'
require 'json'

module WebAppHelper
  include EmailHelper
  API_URL = 'https://kapianapi.herokuapp.com/api/v1/'

  def login_user(user)
    payload = {user_id: user.id}
    token = JWT.encode payload, ENV['TK_KEY'], 'HS256'
    session[:auth_token] = token
    redirect '/'
  end

  def find_user_by_token(token)
    return nil unless token
    decoded_token = JWT.decode token, ENV['TK_KEY'], true
    payload = decoded_token.first
    User.find_by_id(payload["user_id"])
  end

  def logout_user
    session[:auth_token] = nil
  end

  def send_activation_email_sg(username, password, email,address,full_name,dob)
  payload = {username: username, password: password, email: email, address: address, full_name: full_name, dob: dob}
  token = JWT.encode payload, ENV['TK_KEY'], 'HS256'
  url = request.base_url + '/activate?tk=' + token

  client = SendGrid::Client.new(api_user: ENV['SG_USER'], api_key: ENV['SG_PW'])
  mail = SendGrid::Mail.new do |m|
    m.to = email
    m.from = 'acctservices.emfg@gmail.com'
    m.from_name = 'Account Services at Enigma Manufacturing'
    m.subject = 'Activate your account'
    m.text = "In case you can't read html, copy this link into the address bar of your browser:" + url
    m.html = '<html><body><h1>Click <a href=' + url + '>here</a> to activate your account.</h1></body></html>'
  end

  client.send(mail)

  end

  def send_activation_email(username, password, email,address,full_name,dob)

  payload = {username: username, password: password, email: email, address: address, full_name: full_name, dob: dob}
  token = JWT.encode payload, ENV['TK_KEY'], 'HS256'
  url = request.base_url + '/activate?tk=' + token

  send_reg_email(email,url)

  end

  def send_activation_email_py(username, password, email,address,full_name,dob)
    payload = {username: username, password: password, email: email, address: address, full_name: full_name, dob: dob}
    token = JWT.encode payload, ENV['TK_KEY'], 'HS256'
    url = request.base_url + '/activate?tk=' + token
    Pony.mail(
      :to => email,
      :from => 'acctservices.emfg@gmail.com',
      :subject => 'Activate your account',
      :html_body => '<h1>Click <a href=' + url + '>here</a> to activate your account.</h1>',
      :body => "In case you can't read html, copy this link into the address bar of your browser:" + url
    )
  end

  def create_user(token)
    if token == nil || token == "" then
      { :message => "Hi, nice to meet you."}
    elsif JWT.decode(token, ENV['TK_KEY'], true).kind_of?(Array) == false then
      { :message => "What are you trying to pull, slick?"}
    else
      decoded_token = JWT.decode token, ENV['TK_KEY'], true
      payload = decoded_token.first
      newuser = User.new(username: payload["username"], email: payload["email"])
      newuser.password = payload["password"]
      newuser.field_encrypt(payload["address"],:address)
      newuser.field_encrypt(payload["full_name"],:full_name)
      newuser.field_encrypt(payload["dob"],:dob)
      if newuser.save! then
        send_welcome_email(newuser.email)
        { :message => "You are good to go. Enjoy our wonderful API."}
      else
        { :message => "Something went really wrong while activating your account."}
      end
    end
  end
  
  def user_jwt 
    jwt_payload = {'iss' => 'https://kapianweb.herokuapp.com', 'sub' =>  @current_user.id}
    jwt_key = OpenSSL::PKey::RSA.new(ENV['UI_PRIVATE_KEY'])
    JWT.encode jwt_payload, jwt_key, 'RS256'
  end

  def cards_jwt(number, owner, expiration, network)
    url = API_URL + 'credit_card?user_id='+ @current_user.id.to_s
    body_json = {card_number: number, owner: owner, expiration_date: expiration, credit_network: network}.to_json
    headers = {'Authorization' => ('Bearer ' + user_jwt)}
    HTTParty.post url, body: body_json, headers: headers
  end

  def usercard
     url = API_URL + 'credit_card?user_id='+ @current_user.id.to_s
     body_json = {user_id: @current_user.id.to_s}
     headers = {'Authorization' => ('Bearer ' + user_jwt)}
     HTTParty.get url, body: body_json, headers: headers
  end

   def create_account_with_registration(username, email, token)
     new_user = User.new(username: username, email: email)
     new_user.password = token
     if new_user.save! then
        send_welcome_email(new_user.email)
        { :message => "You are good to go. Enjoy our wonderful API."}
     else
        { :message => "Something went really wrong while activating your account."}
     end
   login_user(new_user)
   end
   
   def find_user_by_username(username)
     User.find_by_username(username)
   end
end
