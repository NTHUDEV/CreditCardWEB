require 'sinatra'
require 'rbnacl/libsodium'
require 'config_env'
require_relative './model/user.rb'
require_relative './helpers/web_helper.rb'
require 'haml'
require 'rack-flash'
require 'rack/ssl-enforcer'
require 'dalli'

class WebAppCC < Sinatra::Base
  include WebAppHelper

configure :production do
  use Rack::SslEnforcer
  set :session_secret, ENV['MSG_KEY']
end

configure :development, :test do
  ConfigEnv.path_to_config("./config/config_env.rb")
  require 'hirb'
  Hirb.enable
end

configure do
  use Rack::Session::Cookie, secret: settings.session_secret
  ##use Rack::Session::Cookie, secret: ENV['TK_KEY']
  enable :logging
  use Rack::Flash, :sweep => true
end
configure do
  hirb.enable
  set :ops_cache, Dalli::Client.new((ENV['MEMCACHIER_SERVERS'] || "").split(","),
     {:username => ENV['MEMCACHIER_USERNAME'],
      :password => ENV['MEMCACHIER_PASSWORD'];
      :socket_timeout => 1.5,
      :socket_failure_delay => 0.2
     })
end
before do
@current_user = find_user_by_token(session[:auth_token])
end

register do
  def auth(*types)
    condition do
      if (types.include? :user) && !@current_user
        flash[:error]  = "You must be logged in to enjoy that service."
        redirect "/login"
      end
    end
  end
end


#web app
get '/' do
  haml :index
end

get '/login' do
  haml :login
end

post '/login' do
  username = params[:username]
  password = params[:password]

  user = User.authenticate!(username,password)
  user ? login_user(user) : flash[:error] = "username or password incorrect";redirect('/')
end

get '/logout' do
  logout_user
  flash[:notice] = "You have been logged out. Now get out."
  redirect '/'
end

get '/register' do
  haml :register
end

post '/register' do
  logger.info('REGISTER')

  begin
    if params[:password] == params[:password_confirm]
      fail('You did not specify a user name.') unless params[:username] != ""
      fail('Nice try smartass. Password cannot be blank.') unless params[:password] !=""
      fail('So...where do you live?') unless params[:address] !=""
      fail('You do not expect us to call by your username...right?') unless params[:full_name] !=""
      fail('Yeah, we need your DOB even though you are hiding it.') unless params[:dob] !=""

      send_activation_email(params[:username],params[:password],params[:email],params[:address],params[:full_name],params[:dob]) ? redirect('/success') : fail("Whoops, our bad. Something went terribly wrong with the nuclear codes.")

    else
      fail('Passwords do not match.')
    end
  rescue => e
    logger.error(e)
    flash[:error] = "#{e}"
    redirect '/register'

  end
end

get '/success' do
  haml :registration_success
end

get '/activate' do
  @activation_results = create_user(params[:tk])
  haml :activate
end

get '/newcard', :auth => [:user] do
  haml :newcard
end

post '/newcard' do
  begin
      cc_num = params[:card_number].to_s unless params[:card_number].empty?
      cc_owner = params[:owner].to_s unless params[:owner].empty?
      cc_expiration = params[:expiration_date].to_s unless params[:expiration_date].empty?
      cc_network = params[:network].to_s unless params[:network].empty?
      @created = cards_jwt(cc_num, cc_owner, cc_expiration, cc_network)
      haml :newcard
  
   rescue => e
     puts e
       halt 400, "Check the parameters, it's seems you are in trouble"
    end
end
get '/token', :auth => [:user] do
  user_jwt
end


get '/user/:username', :auth => [:user] do
  username = params[:username]
  unless username == @current_user.username
    flash[:error] = "You may only look at your own profile, please put your username after ../user/"
    redirect '/'
  end
  haml :profile
end

get '/usercards', :auth => [:user] do
  @tablecards = usercard
  haml :usercards
end

 get '/callback' do
   gh = HTTParty.post('https://github.com/login/oauth/access_token', 
        body: {client_id: ENV['GH_CLIENT_ID'], client_secret: ENV['GH_CLIENT_SECRET'], code: params['code']},
        headers: {'Accept' => 'application/json'})
   gh_user = HTTParty.get(
        'https://api.github.com/user',
        body: {params: {access_token: gh['access_token']}},
        headers: {'User-Agent' => 'Credit Card APP', 'Authorization' => "token #{gh['access_token']}"})
   username = gh_user['login']
   email = gh_user['email']
   if user = find_user_by_username(username)
     login_user(user)
   else
     create_account_with_registration(username, email, gh['access_token'])
   end
     redirect '/'
 end


end
