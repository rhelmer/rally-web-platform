<script>
  /* This Source Code Form is subject to the terms of the Mozilla Public
   * License, v. 2.0. If a copy of the MPL was not distributed with this
   * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
  import { onMount } from "svelte";
  import { Meta, Template, Story } from "@storybook/addon-svelte-csf";
  import Card from "../../lib/components/Card.svelte";

  let titleEl;
  let textWidth;

  onMount(async () => {
    if (titleEl) {
      await titleEl;
      textWidth = titleEl.clientWidth;
    }
  });

  $: cssVarStyles = `--titleWidth:${textWidth}px`;
</script>

<Meta
  title="Components/Cards/Check Email"
  component={Card}
  argTypes={{
    title: { control: "text" },
    body: { control: "text" },
    bodyText: { control: "text" },
    cta1: { control: "text" },
    cta2: { control: "text" },
    width: { control: "text" },
    height: { control: "text" },
    fontSize: { control: "text" },
    linkText: { control: "text" },
    custom: { control: "text" },
    minHeight: { control: "text" },
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

      <div class="card-content card-content--info" slot="card-content">
        <p class="card-content__text">{args.body}</p>
      </div>

      <div slot="cta" class="body-text-action body-text-action--info">
        Ready to sign in? <button>Sign in</button>
        <p class="contact-text">
          {args.bodyText} <a href="/">{args.linkText}</a>
        </p>
      </div>
    </Card>
  </div>
</Template>

<!-- 👇 Each story then reuses that template -->
<Story
  name="Confirm Email"
  args={{
    width: "368px",
    height: "auto",
    fontSize: "38px",
    title: "Check your email",
    body:
      "To finish creating your account with Rally, please check your email inbox and verify your email address.",
    bodyText: "Need help?",
    linkText: "Contact Us",
    custom: "info-card",
  }}
/>

<Story
  name="Reset Password Email"
  args={{
    width: "368px",
    height: "auto",
    fontSize: "38px",
    title: "Check your email",
    body:
      "Instructions to reset your password have been sent to [example@workmail.com]",
    bodyText: "Need help?",
    linkText: "Contact Us",
    custom: "info-card",
  }}
/>

<style>
  .sb-container {
    padding: 2rem 1rem;
  }
  .title-highlight {
    width: calc(var(--titleWidth) + 15px);
  }
</style>
