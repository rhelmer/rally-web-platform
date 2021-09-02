import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

import { studies } from "./studies";
import { v4 as uuidv4 } from "uuid";

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
