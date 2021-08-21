/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

 import { Builder } from "selenium-webdriver";
 import firefox from "selenium-webdriver/firefox";
 import fs from "fs";
 
 /**
  * Get a Selenium driver for using the Firefox browser.
  *
  * @param {Boolean} headless
  *        Whether or not to run Firefox in headless mode.
  * @returns {WebDriver} a WebDriver instance to control Firefox.
  */
 export async function getFirefoxDriver(headless) {
   const firefoxOptions = new firefox.Options();
   firefoxOptions.setPreference("xpinstall.signatures.required", false);
   firefoxOptions.setPreference("extensions.experiments.enabled", true);
 
   if (headless) {
     firefoxOptions.headless();
   }
 
   if (process.platform === "linux") {
     // Look for the Firefox executable in different locations.
     const FIREFOX_PATHS = [
       "/usr/bin/firefox-trunk",
       "/usr/bin/firefox",
     ];
 
     for (const path of FIREFOX_PATHS) {
       if (fs.existsSync(path)) {
         firefoxOptions.setBinary(path);
         break;
       }
     }
   } else if (process.platform === "darwin") {
     firefoxOptions.setBinary(
       "/Applications/Firefox Nightly.app/Contents/MacOS/firefox"
     );
   }

   // firefoxOptions.addExtensions(`${__dirname}/extension.xpi`);
 
   return await new Builder()
     .forBrowser("firefox")
     .setFirefoxOptions(firefoxOptions)
     .build();
 }