# Platform-Mock UI Layout and Key Modal Redesign Plan

## 1. Work Items Breakdown
- [x] Task 1: Update HTML Template (`tools/platform-mock/internal/static/index.html`)
  - Remove `<nav class="pipeline-stepper" id="pipelineStepper">` and its nested step elements.
  - Remove `#registerPublicKeyBox` from `#card-attestation`.
  - Add `#taaPublicKeyBtn` in `#card-attestation` header actions.
  - Add `#taaPublicKeyModal` overlay at the bottom with `#copyPubKeyBtn`, close button, and `#registerPublicKey` textarea.
  - Restructure `#card-importModel` to place "随机 ID" button on the left of side-by-side `requestId` and `taskId` fields; clean up bottom actions.
  - Restructure `#card-import` to place "随机 ID" button on the left of side-by-side `requestId` and `taskId` fields; clean up bottom actions.
- [x] Task 2: Update CSS Styles (`tools/platform-mock/internal/static/css/components.css`)
  - Add `.id-input-row`, `.id-inputs-cols`, `.id-input-col`, and refine `.btn-field-random` styling.
  - Ensure responsive wrapping and height alignment.
- [x] Task 3: Update JavaScript Logic (`tools/platform-mock/internal/static/js/app.js` and `drawer.js`)
  - Add `openTaaPublicKeyModal` and `closeTaaPublicKeyModal` functions.
  - Update `renderRegister` to toggle `#taaPublicKeyBtn` enabled/disabled state.
  - Add null check to `syncStepperState`.
  - Add Escape key handling for `#taaPublicKeyModal`.
- [x] Task 4: Update Automated Tests (`tools/platform-mock/internal/server_test.go`)
  - Adjust stepper-related assertions to reflect removed stepper and new modal/button patterns.
  - Verify all Go unit and integration tests pass via `go test ./...`.
- [x] Task 5: Build Verification and Git Commit
  - Build `bin/taa` and `bin/platform-mock`.
  - Execute git commit following Conventional Commits without AI signatures.
