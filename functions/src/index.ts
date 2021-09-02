import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

import Glean from "@mozilla/glean/webext";
import PingEncryptionPlugin from "@mozilla/glean/webext/plugins/encryption";

import * as rallyMetrics from "../public/generated/rally";
import * as userMetrics from "../public/generated/user";
import * as enrollmentMetrics from "../public/generated/enrollment";
import * as unenrollmentMetrics from "../public/generated/unenrollment";
import * as rallyPings from "../public/generated/pings";

import { studies } from "./studies";
import { v4 as uuidv4 } from "uuid";

const GLEAN_ENCRYPTION_JWK = {
  "crv": "P-256",
  "kid": "rally-core",
  "kty": "EC",
  "x": "m7Gi2YD8DgPg3zxora5iwf0DFL0JFIhjoD2BRLpg7kI",
  "y": "zo35XIQME7Ct01uHK_LrMi5pZCuYDMhv8MUsSu7Eq08",
};

admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

export const rallytoken = functions.https.onRequest(
  async (request, response) => {
    response.set("Access-Control-Allow-Origin", "*");
    response.set("Access-Control-Allow-Headers", "Content-Type");

    if (request.method === "OPTIONS") {
      response.set("Access-Control-Allow-Methods", "POST");
      response.set("Access-Control-Allow-Headers", "Bearer, Content-Type");
      response.status(204).send("");
    } else if (request.method === "POST") {
      functions.logger.info(
        `body type: ${typeof request.body}`,
        { payload: request.body }
      );

      try {
        let idToken;
        let studyId;
        if (typeof request.body === "string") {
          const body = JSON.parse(request.body);
          idToken = body.idToken;
          studyId = body.studyId;
        } else {
          idToken = request.body.idToken;
          studyId = request.body.studyId;
        }

        const rallyToken = await generateToken(idToken, studyId);
        functions.logger.info("OK");
        response.status(200).send({ rallyToken });
      } catch (ex) {
        functions.logger.error(ex);
        response.status(500).send(ex.message);
      }
    } else {
      response.status(500).send("Only POST and OPTIONS methods are allowed.");
    }
  }
);

/**
 * Takes a Firebase IDToken for a Rally user, and returns a Rally Token
 * for a restricted-access account (for use with studies).
 *
 * @param {string} idToken Firebase IDToken.
 * @param {string} studyId Rally study ID.
 * @return {Promise<string>} rallyToken
 */
async function generateToken(idToken: string, studyId: string) {
  const decodedToken = await admin.auth().verifyIdToken(idToken);

  // Firebase will create this account if it does not exist,
  // when the token is first used to sign-in.
  const uid = `${studyId}:${decodedToken.uid}`;
  const rallyToken = await admin.auth().createCustomToken(
    uid, { firebaseUid: decodedToken.uid, studyId }
  );

  return rallyToken;
}

exports.addRallyUserToFirestore = functions.auth.user().onCreate(
  async (user) => {
    functions.logger.info("addRallyUserToFirestore fired");
    if (user.providerData.length == 0) {
      functions.logger.info("Extension users do not get user docs.");
      return;
    }

    const newRallyId = uuidv4();
    const extensionUserDoc = { rallyId: newRallyId };
    admin
      .firestore()
      .collection("extensionUsers")
      .doc(user.uid)
      .set(extensionUserDoc, { merge: true });

    const userDoc = {
      createdOn: new Date(),
      uid: user.uid,
    };
    admin
      .firestore()
      .collection("users")
      .doc(user.uid)
      .set(userDoc, { merge: true });

    return true;
  }
);

exports.deleteRallyUser = functions.auth.user().onDelete(
  async (user) => {
    functions.logger.info("deleteRallyUser fired");

    // Delete the extension user document.
    admin
      .firestore()
      .collection("extensionUsers")
      .doc(user.uid)
      .delete();

    // Delete the user studies subcollection.
    const collectionRef = admin
      .firestore()
      .collection("users")
      .doc(user.uid)
      .collection("studies");

    // There will never be more of these than there are studies, which
    // is why we're not worried about batching. If it does become a problem (over 500
    // documents, per https://firebase.google.com/docs/firestore/manage-data/transactions),
    // then see: https://firebase.google.com/docs/firestore/manage-data/delete-data#collections
    //
    // You might also consider: https://firebase.google.com/docs/firestore/solutions/delete-collections
    const userStudyDocs = await collectionRef.get();
    userStudyDocs.forEach(async (userStudyDoc) => {
      await userStudyDoc.ref.delete();
    });

    // Finally, delete the user document.
    admin
      .firestore()
      .collection("users")
      .doc(user.uid)
      .delete();

    return true;
  }
);

async function getRallyId(userId: string) {
  const extensionUserRef = await admin
    .firestore()
    .collection("extensionUsers")
    .doc(userId)
    .get();

  const extensionUserDoc = extensionUserRef.data();
  if (!extensionUserDoc) {
    throw new Error(`No extension user doc for user ID ${userId}`);
  }

  if (!extensionUserDoc.rallyId) {
    throw new Error(`No rallyId field in extension user doc for user ID ${userId}`);
  }

  const rallyId = extensionUserDoc.rallyId;
  return rallyId;
}

exports.handleUserChanges = functions.firestore
  .document('users/{userID}')
  .onWrite(async (change, context) => {
    const userId = context.params.userId;
    // Get an object with the current document value.
    // If the document does not exist, it has been deleted.
    const document = change.after.exists ? change.after.data() : null;

    // Get the old document, to compare the enrollment state.
    // const oldDocument = change.before.data();

    if (!document) {
      throw new Error(`No user document for user ID ${userId}`);
    }
    if (!document.enrolled) {
      throw new Error(`No enrolled field in user document for user ID ${userId}`)
    }

    if (!document.demographicsData) {
      throw new Error(`No demographics field in user document for user ID ${userId}`);
    }

    // TODO if demographics changed
    await sendDemographicsPing(document.demographicsData);

    const rallyId = await getRallyId(userId);

    if (document.enrolled === "true") {
      await sendPlatformEnrollmentPing(rallyId);
    } else {
      await sendPlatformDeletionPing(rallyId);
    }
  });

exports.handleUserStudyChanges = functions.firestore
  .document('users/{userID}/studies/{studyId}')
  .onWrite(async (change, context) => {
    const userId = context.params.userId;
    const studyId = context.params.studyId;
    // Get an object with the current document value.
    // If the document does not exist, it has been deleted.
    const document = change.after.exists ? change.after.data() : null;

    // Get the old document, to compare the enrollment state.
    // const oldDocument = change.before.data();

    if (!document) {
      throw new Error(`No userStudy document for user ID ${userId} with study ID ${studyId}`);
    }

    if (!document.studyId) {
      throw new Error(`User ID ${userId} missing study ID in `)
    }

    if (!document.enrolled) {
      throw new Error(`No enrolled field in user studies document for user ID ${userId} with study ID ${studyId}`)
    }

    const rallyId = await getRallyId(userId);

    if (document.enrolled === true) {
      await sendStudyEnrollmentPing(rallyId, studyId)
    } else if (document.enrolled === false) {
      await sendStudyDeletionPing(rallyId, studyId);
    } else {
      throw new Error(`document.enrolled not boolean for user ID ${userId} with study ID ${studyId}`);
    }
  });

async function sendPlatformEnrollmentPing(rallyId: string) {
  Glean.initialize("rally-core", true, {
    appDisplayVersion: "TODO-rally-firestore-server",
    plugins: [
      new PingEncryptionPlugin(GLEAN_ENCRYPTION_JWK)
    ]
  });

  rallyMetrics.id.set(rallyId);

  Glean.setUploadEnabled(true);

  rallyMetrics.id.set(rallyId);

  rallyPings.enrollment.submit();

  // Wait for Glean to finish sending pending pings.
  await Glean.shutdown();
}

async function sendPlatformDeletionPing(rallyId: string) {
  Glean.initialize("rally-core", true, {
    appDisplayVersion: "TODO-rally-firestore-server",
    plugins: [
      new PingEncryptionPlugin(GLEAN_ENCRYPTION_JWK)
    ]
  });

  rallyMetrics.id.set(rallyId);

  // Flip upload enabled to disabled: this will trigger a
  // deletion-request.
  Glean.setUploadEnabled(false);

  // Wait for Glean to finish sending pending pings.
  await Glean.shutdown();
}

async function sendStudyEnrollmentPing(rallyId: string, studyId: string) {
  Glean.initialize("rally-core", true, {
    appDisplayVersion: "TODO-rally-firestore-server",
    plugins: [
      new PingEncryptionPlugin(GLEAN_ENCRYPTION_JWK)
    ]
  });

  Glean.setUploadEnabled(true);

  rallyMetrics.id.set(rallyId);

  enrollmentMetrics.studyId.set(studyId);
  rallyPings.studyEnrollment.submit();

  // Wait for Glean to finish sending pending pings.
  await Glean.shutdown();
}

async function sendStudyDeletionPing(rallyId: string, studyId: string) {
  Glean.initialize("rally-core", true, {
    appDisplayVersion: "TODO-rally-firestore-server",
    plugins: [
      new PingEncryptionPlugin(GLEAN_ENCRYPTION_JWK)
    ]
  });

  Glean.setUploadEnabled(true);

  unenrollmentMetrics.studyId.set(studyId);
  rallyPings.studyUnenrollment.submit();

  // Wait for Glean to finish sending pending pings.
  await Glean.shutdown();
}

/**
 * Sends a demographic-survey ping with Glean.js.
 *
 * @param {Object} data
 *        A JSON-serializable object containing the demographics
 *        information submitted by the user..
 */
async function sendDemographicsPing(data: { [x: string]: any; }) {
  Glean.initialize("rally-core", true, {
    appDisplayVersion: "TODO-rally-firestore-server",
    plugins: [
      new PingEncryptionPlugin(GLEAN_ENCRYPTION_JWK)
    ]
  });

  Glean.setUploadEnabled(true);

  // The schema for the non-glean collection is hard to change.
  // In order for us to not change it, we transform the provided
  // fields in a way that's expected by Glean.

  if ("age" in data) {
    userMetrics.age[`band_${data["age"]}`].set(true);
  }

  if ("gender" in data) {
    userMetrics.gender[data["gender"]].set(true);
  }

  if ("hispanicLatinxSpanishOrigin" in data) {
    const label = (data["hispanicLatinxSpanishOrigin"] === "other")
      ? "other" : "hispanicLatinxSpanish";
    userMetrics.origin[label].set(true);
  }

  if ("race" in data) {
    for (const raceLabel of data["race"]) {
      const label = (raceLabel === "american_indian_or_alaska_native")
        ? "am_indian_or_alaska_native" : raceLabel;
      userMetrics.races[label].set(true);
    }
  }

  if ("school" in data) {
    const KEY_FIXUP = {
      "high_school_graduate_or_equivalent": "high_school_grad_or_eq",
      "some_college_but_no_degree_or_in_progress": "college_degree_in_progress",
    };

    const originalLabel = data["school"];
    const label = (originalLabel in KEY_FIXUP)
      //@ts-ignore FIXME
      ? KEY_FIXUP[originalLabel] : originalLabel;
    userMetrics.school[label].set(true);
  }

  if ("exactIncome" in data) {
    userMetrics.exactIncome.set(data['exactIncome']);
  }

  if ("zipcode" in data) {
    userMetrics.zipcode.set(data["zipcode"]);
  }

  rallyPings.demographics.submit();

  // Wait for Glean to finish sending pending pings.
  await Glean.shutdown();
}

/**
 *
 * @param {string} index The firestore key.
 * @param {object} study The study object.
 */
function addRallyStudyToFirestore(index: string,
  study: Record<string, unknown>) {
  admin
    .firestore()
    .collection("studies")
    .doc(index)
    .set(study, { merge: true });
}

export const loadFirestore = functions.https.onRequest(
  async (request, response) => {
    for (const [index, study] of Object.entries(studies)) {
      console.info(`Loading study ${index} into Firestore`);
      addRallyStudyToFirestore(index, study);
    }
    response.status(200).send();
  }
);
