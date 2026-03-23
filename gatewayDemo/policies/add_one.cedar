@id("allow_one")
permit(
  principal,
  action,
  resource is Jans::HTTP_Request
)
when {
  context has tokens.jans_access_token &&
  context.tokens.jans_access_token.hasTag("scope") &&
  context.tokens.jans_access_token.getTag("scope").contains("openid")
};