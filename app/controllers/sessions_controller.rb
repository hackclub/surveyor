class SessionsController < ApplicationController
  def new
    redirect_uri = url_for(action: :create, only_path: false)
    Rails.logger.info "Starting Slack OAuth flow with redirect URI: #{redirect_uri}"
    redirect_to authorize_url(redirect_uri, close_window: params[:close_window].present?, continue_param: params[:continue]),
                host: "https://slack.com",
                allow_other_host: "https://slack.com"
  end

  def create
    # Handle the callback from Slack
    redirect_uri = url_for(action: :create, only_path: false)
    @user = User.from_slack_token(params[:code], redirect_uri)

    if @user&.persisted?
      session[:user_id] = @user.id
      redirect_to root_path, notice: "Successfully signed in with Slack! Welcome!"
    else
      Rails.logger.error "Failed to create/update user from Slack data"
      redirect_to root_path, alert: "Failed to sign in with Slack"
    end
  end

  private

  def authorize_url(redirect_uri, close_window: false, continue_param: nil)
    state = {
      token: SecureRandom.hex(24),
      close_window: close_window,
      continue: continue_param
    }.to_json

    params = {
      client_id: ENV["SLACK_CLIENT_ID"],
      redirect_uri: redirect_uri,
      state: state,
      user_scope: "users.profile:read,users.profile:write,users:read,users:read.email"
    }

    URI.parse("https://slack.com/oauth/v2/authorize?#{params.to_query}")
  end
end
