require 'sinatra'
require 'rbnacl/libsodium'
require 'config_env'
require_relative './model/user.rb'
require_relative './helpers/web_helper.rb'
require 'haml'
require 'rack-flash'
require 'rack/ssl-enforcer'

class WebAppCC < Sinatra::Base
  include WebAppHelper

configure :production do
  use RacK::SslEnforcer
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

before do
@current_user = find_user_by_token(session[:auth_token])
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
  user ? login_user(user) : redirect('/')
end

get '/logout' do
  logout_user
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
  ##rescue => e
    ##logger.error(e)
    ##flash[:error] = "#{e}"
    ##redirect '/register'

  end
end



get '/success' do
  haml :registration_success
end

get '/activate' do
  @activation_results = create_user(params[:tk])
  haml :activate
end
end
