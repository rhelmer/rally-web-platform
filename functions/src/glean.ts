import Glean from "@mozilla/glean/node";
import PingEncryptionPlugin from "@mozilla/glean/plugins/encryption";
import axios from "axios";
import functions from "firebase-functions";
import { Mutex, Semaphore, withTimeout } from "async-mutex";
import fs from "fs";

const RWP_pkg = JSON.parse(fs.readFileSync("package.json").toString());

import * as rallyMetrics from "./generated/rally.js";
import * as userMetrics from "./generated/user.js";
import * as enrollmentMetrics from "./generated/enrollment.js";
import * as unenrollmentMetrics from "./generated/unenrollment.js";
import * as rallyPings from "./generated/pings.js";

import {
  Uploader,
  UploadResult,
  UploadResultStatus,
} from "@mozilla/glean/uploader";

const GLEAN_DEBUG_VIEW_TAG = "MozillaRally";
const ENABLE_GLEAN =
  process.env.ENABLE_GLEAN || !process.env.FUNCTIONS_EMULATOR;
const GLEAN_RALLY_APP_ID = process.env.FUNCTIONS_EMULATOR
  ? "test-app-id"
  : "rally-core";
const GLEAN_APP_DISPLAY_VERSION = RWP_pkg.version;
const GLEAN_ENCRYPTION_JWK = {
  crv: "P-256",
  kid: "rally-core",
  kty: "EC",
  x: "m7Gi2YD8DgPg3zxora5iwf0DFL0JFIhjoD2BRLpg7kI",
  y: "zo35XIQME7Ct01uHK_LrMi5pZCuYDMhv8MUsSu7Eq08",
};

const GLEAN_DEFAULT_TIMEOUT = 10000;
const gleanLock = withTimeout(new Mutex(), GLEAN_DEFAULT_TIMEOUT); // Lock on global Glean instance, metrics, and pings
const submitPingFlag = withTimeout(new Semaphore(1), GLEAN_DEFAULT_TIMEOUT); // Allow Glean to signal once ping is sent

/*
 * platformEnrollment
 * Glean ping: enrollment
 */
export async function platformEnrollment(rallyID: string): Promise<void> {
  if (!ENABLE_GLEAN) return;
  const releaseGlean = await gleanLock.acquire();
  initializeGlean();

  rallyMetrics.id.set(rallyID);

  await submitPingFlag.acquire();
  rallyPings.enrollment.submit();
  await submitPingFlag.waitForUnlock();

  releaseGlean();
}

/*
 * platformUnenrollment
 * Glean ping: unenrollment
 *
 */
export async function platformUnenrollment(rallyID: string): Promise<void> {
  if (!ENABLE_GLEAN) return;
  const releaseGlean = await gleanLock.acquire();
  initializeGlean();

  rallyMetrics.id.set(rallyID);

  await submitPingFlag.acquire();
  rallyPings.unenrollment.submit();
  await submitPingFlag.waitForUnlock();

  releaseGlean();
}

/*
 * demographics
 * Glean ping: demographics
 */
export async function demographics(
  rallyID: string,
  demographicsData: Record<string, unknown>
): Promise<void> {
  if (!ENABLE_GLEAN) return;
  const releaseGlean = await gleanLock.acquire();
  initializeGlean();

  rallyMetrics.id.set(rallyID);
  setUserMetrics(demographicsData);

  await submitPingFlag.acquire();
  rallyPings.demographics.submit();
  await submitPingFlag.waitForUnlock();

  releaseGlean();
}

/*
 * studyEnrollment
 * Glean ping: study-enrollment
 */
export async function studyEnrollment(
  rallyID: string,
  studyID: string
): Promise<void> {
  if (!ENABLE_GLEAN) return;
  const releaseGlean = await gleanLock.acquire();
  initializeGlean();

  rallyMetrics.id.set(rallyID);
  enrollmentMetrics.studyId.set(studyID);

  await submitPingFlag.acquire();
  rallyPings.studyEnrollment.submit();
  await submitPingFlag.waitForUnlock();

  releaseGlean();
}

/*
 * studyUnenrollment
 * Glean ping: study-unenrollment
 */
export async function studyUnenrollment(
  rallyID: string,
  studyID: string
): Promise<void> {
  if (!ENABLE_GLEAN) return;
  const releaseGlean = await gleanLock.acquire();
  initializeGlean();

  rallyMetrics.id.set(rallyID);
  unenrollmentMetrics.studyId.set(studyID);

  await submitPingFlag.acquire();
  rallyPings.studyUnenrollment.submit();
  await submitPingFlag.waitForUnlock();

  releaseGlean();
}

/*
 * Helper function for initializing Glean
 */
function initializeGlean(): void {
  if (!ENABLE_GLEAN) return;

  if (process.env.FUNCTIONS_EMULATOR) {
    Glean.setDebugViewTag(GLEAN_DEBUG_VIEW_TAG);
    Glean.setLogPings(true);
  }

  // Glean.initialize is a no-op if Glean is already initialized
  Glean.initialize(GLEAN_RALLY_APP_ID, true, {
    appDisplayVersion: GLEAN_APP_DISPLAY_VERSION,
    plugins: [new PingEncryptionPlugin(GLEAN_ENCRYPTION_JWK)],
    httpClient: new CustomPingUploader(),
  });
}

/*
 * Helper function for setting user metrics
 * from demographic data (mapping)
 */
function setUserMetrics(data: any): void { // eslint-disable-line @typescript-eslint/no-explicit-any
  if (!data) return;

  if ("age" in data) {
    userMetrics.age[`band_${data["age"]}`].set(true);
  }

  if ("gender" in data) {
    userMetrics.gender[data["gender"]].set(true);
  }

  if ("hispanicLatinxSpanishOrigin" in data) {
    const label =
      data["hispanicLatinxSpanishOrigin"] === "other"
        ? "other"
        : "hispanic_latinx_spanish";
    userMetrics.origin[label].set(true);
  }

  if ("race" in data) {
    for (const raceLabel of data["race"]) {
      const label =
        raceLabel === "american_indian_or_alaska_native"
          ? "am_indian_or_alaska_native"
          : raceLabel;
      userMetrics.races[label].set(true);
    }
  }

  if ("school" in data) {
    const KEY_FIXUP: any = { // eslint-disable-line @typescript-eslint/no-explicit-any
      high_school_graduate_or_equivalent: "high_school_grad_or_eq",
      some_college_but_no_degree_or_in_progress: "college_degree_in_progress",
    };

    const originalLabel = data["school"];
    const label =
      originalLabel in KEY_FIXUP ? KEY_FIXUP[originalLabel] : originalLabel;
    userMetrics.school[label].set(true);
  }

  if ("exactIncome" in data) {
    userMetrics.exactIncome.set(data["exactIncome"]);
  }

  if ("zipcode" in data) {
    userMetrics.zipcode.set(data["zipcode"]);
  }
}

/**
 * Custom Ping Uploader for Glean
 * TODO: replace direct POST request with Google Cloud Task
 */
class CustomPingUploader extends Uploader {
  async post(
    url: string,
    body: string | Uint8Array,
    headers: Record<string, string>
  ): Promise<UploadResult> {
    const result = await axios
      .post(url, body, { headers: headers })
      .then(function (response) {
        return {
          status: response.status,
          result: UploadResultStatus.Success,
        };
      })
      .catch(function (error) {
        functions.logger.error(error);
        return {
          status: 500,
          result: UploadResultStatus.UnrecoverableFailure,
        };
      });

    // Signal to ping function that ping has been submitted
    submitPingFlag.release();
    return result;
  }
}
