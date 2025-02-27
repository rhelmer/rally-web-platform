<script>
  import { onMount } from "svelte";
  import { Meta, Template, Story } from "@storybook/addon-svelte-csf";
  import Card from "../../lib/components/Card.svelte";
  import Button from "../../lib/components/Button.svelte";

  let titleEl;
  let textWidth;

  let email;
  let password;
  let passwordEl;
  let passwordVisible = false;
  let btnDisabled = true;
  let number;
  let length;
  let capital;
  let letter;
  const minPasswordLength = 8;
  let pattern = "(?=.*d)(?=.*[a-z])(?=.*[A-Z]).{8,}";
  let formHeight = "auto";

  onMount(async () => {
    if (titleEl) {
      await titleEl;
      textWidth = titleEl.clientWidth;
    }
  });

  $: cssVarStyles = `--titleWidth:${textWidth}px`;
  $: formStyles = `--formHeight:${formHeight}`;

  const handleToggle = () => {
    passwordVisible = !passwordVisible;
    const type =
      passwordEl.getAttribute("type") === "password" ? "text" : "password";
    passwordEl.setAttribute("type", type);
  };

  const handleChange = (e) => {
    const name = e.srcElement.name;
    if (passwordEl) {
      // Validate lowercase letters
      let lowerCaseLetters = /[a-z]/g;
      passwordEl.value.match(lowerCaseLetters)
        ? letter.classList.add("valid")
        : letter.classList.remove("valid");

      // Validate capital letters
      let upperCaseLetters = /[A-Z]/g;
      passwordEl.value.match(upperCaseLetters)
        ? capital.classList.add("valid")
        : capital.classList.remove("valid");

      // Validate numbers
      let numbers = /[0-9]/g;
      passwordEl.value.match(numbers)
        ? number.classList.add("valid")
        : number.classList.remove("valid");

      // Validate length
      passwordEl.value.length >= 8
        ? length.classList.add("valid")
        : length.classList.remove("valid");
      if (name === "id_user_pw") {
        if (
          passwordEl.value.length >= minPasswordLength &&
          passwordEl.value.match(numbers) &&
          passwordEl.value.match(upperCaseLetters) &&
          passwordEl.value.match(lowerCaseLetters)
        ) {
          btnDisabled = false;
        } else {
          btnDisabled = true;
        }
      }
    }
  };
</script>

<Meta
  title="Components/Cards/Create Account"
  component={Card}
  argTypes={{
    title: { control: "text" },
    body: { control: "text" },
    cta1: { control: "text" },
    cta2: { control: "text" },
    width: { control: "text" },
    height: { control: "text" },
    fontSize: { control: "text" },
    bodyText: { control: "text" },
    linkText: { control: "text" },
  }}
/>

<!-- 👇 We create a “template” of how args map to rendering -->
<Template let:args>
  <div class="sb-container">
    <Card {...args}>
      <h2 class="title-wrapper" slot="card-title">
        <div style={cssVarStyles} class="title-highlight" />
        <div bind:this={titleEl} class="title-text">{args.title}</div>
      </h2>

      <div class="card-content card-content--form" slot="card-content">
        <div class="form-wrapper">
          <form method="post" style={formStyles}>
            <fieldset class="mzp-c-field-set field-set">
              <div class="mzp-c-field field field--email">
                <div class="label-wrapper">
                  <label class="mzp-c-field-label" for="id_user_pw">Email</label
                  >
                </div>

                <input
                  class="mzp-c-field-control"
                  bind:value={email}
                  on:change={handleChange}
                  on:keyup={handleChange}
                  id="id_user_email"
                  name="id_user_email"
                  type="email"
                  width="100%"
                  placeholder="Enter your email address"
                  required
                />
              </div>

              <!-- PASSWORD -->
              <div class="mzp-c-field field field--pw">
                <div class="label-wrapper">
                  <label class="mzp-c-field-label" for="id_user_pw"
                    >Password</label
                  >
                </div>

                <div class="input-wrapper">
                  <input
                    class="mzp-c-field-control"
                    bind:value={password}
                    bind:this={passwordEl}
                    on:change={handleChange}
                    on:keyup={handleChange}
                    id="id_user_pw"
                    name="id_user_pw"
                    type="password"
                    {pattern}
                    width="100%"
                    required
                  />
                  {#if passwordVisible}
                    <img
                      src="img/eye-slash.svg"
                      alt="Eye with slash across it"
                      class="fas fa-eye-slash togglePassword"
                      id="hide-eye"
                      width="24px"
                      height="24px"
                      on:click|preventDefault={handleToggle}
                    />
                  {:else}
                    <img
                      src="img/eye-open.svg"
                      alt="Open eye"
                      class="togglePassword"
                      id="show-eye"
                      width="24px"
                      height="24px"
                      on:click|preventDefault={handleToggle}
                    />
                  {/if}
                </div>

                <ul class="info-rules">
                  <li bind:this={length} id="length">
                    Use at least 8 characters
                  </li>
                  <li bind:this={capital} id="capital">
                    Use at least 1 uppercase letter
                  </li>
                  <li bind:this={letter} id="letter">
                    Use at least 1 lowercase letter
                  </li>
                  <li bind:this={number} id="number">Use at least 1 number</li>
                </ul>
              </div>
            </fieldset>
          </form>
          <Button disabled={btnDisabled} size="xl" custom="card-button card-button--create">
            <div class="button-text--signin">{args.cta1}</div></Button
          >
          <p class="body-text-privacy">
            By proceeding, you agree to our <a href="/">Privacy Notice</a>
          </p>
        </div>
      </div>
      <p slot="cta" class="body-text-action">
        {args.bodyText} <a href="/">{args.linkText}</a>
      </p>
    </Card>
  </div>
</Template>

<!-- 👇 Each story then reuses that template -->

<Story
  name="Create Account"
  args={{
    width: "370px",
    fontSize: "38px",
    height: "auto",
    title: "Create account",
    cta1: "Continue",
    bodyText: "Already have an account?",
    linkText: "Sign in",
    custom: "card-body-create",
  }}
/>

<style>
  .sb-container {
    padding: 2rem 1rem;
  }
  .title-highlight {
    background-color: var(--color-yellow-35);
    border-radius: 4px;
    position: absolute;
    height: 1.375rem;
    width: calc(var(--titleWidth) + 15px);
    margin-top: 24px;
  }
</style>
