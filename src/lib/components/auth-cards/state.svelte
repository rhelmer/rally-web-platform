<script context="module">
  //launch card states
  export const card = {
    welcomeCard: true,
    joinCard: false,
    createAcctCard: false,
    forgetPWCard: false,
    resetPWCard: false,
    checkEmailCard: false,
    checkEmailPWCard: false,
    cardHeight: "auto",
  };

  //card args
  export const argTypes = {
    width: { control: "text" },
    height: { control: "text" },
    topPadding: { control: "text" },
    fontSize: { control: "text" },
  };

  export const cardArgs = {
    width: "370px",
    height: "auto",
  };

  export const welcomeArgs = {
    ...cardArgs,
    title: "Welcome back",
    cta1: "Sign in with Google",
    bodyText: "Don't have an account?",
    linkText: "Create account",
    welcomeCard: card.welcomeCard,
  };
  export const joinArgs = {
    ...cardArgs,
    title: "Join Rally",
    cta1: "Sign up with Google",
    bodyText: "Already have an account?",
    linkText: "Sign in",
  };
  export const createArgs = {
    ...cardArgs,
    custom: "card__body--create",
    height: card.cardHeight,
    title: "Create account",
    cta1: "Continue",
    bodyText: "Already have an account?",
    linkText: "Sign in",
  };

  export const forgetPWArgs = {
    height: "auto",
    width: "391px",
    title: "Forgot your password?",
    cta1: "Reset password",
    bodyText: "We'll send you a link to reset your password.",
  };

  export const resetPWArgs = {
    height: "auto",
    width: "391px",
    title: "Reset your password",
    cta1: "Reset password",
    custom: "reset-pw",
  };

  export const checkEmailPWArgs = {
    ...cardArgs,
    height: "auto",
    title: "Check your email",
    ctaText: "Need help?",
    linkText: "Contact us",
    custom: "info-card",
    checkPW: true,
  };
  export const checkEmailArgs = {
    ...cardArgs,
    height: "auto",
    title: "Check your email",
    ctaText: "Need help?",
    linkText: "Contact us",
    custom: "info-card",
    checkPW: false,
  };
</script>
