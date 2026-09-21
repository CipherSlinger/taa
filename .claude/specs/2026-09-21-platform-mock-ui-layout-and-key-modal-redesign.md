# Platform-Mock UI Layout and Key Modal Redesign Specification

## 1. Overview
This specification details the UI layout optimizations and interaction refinements for the Platform-Mock console (`tools/platform-mock`). The enhancements focus on reducing visual clutter, improving operational ergonomics for input generation, and streamlining security credentials management.

## 2. Requirements & Objectives
1. **Flow Dynamic Stepper Removal**:
   - Remove the top lifecycle pipeline stepper navigation (`#pipelineStepper`) from the main view to provide a more compact, focused console interface.
   - Ensure frontend state synchronization (`syncStepperState`) handles the absence of stepper elements safely without throwing errors.

2. **TAA Public Key Modal & Interaction Migration**:
   - Do not display the TAA registration public key directly in the registration card body.
   - Introduce a dedicated "公钥" (Public Key) button in the platform registration card header.
   - Clicking the button opens a modal window (`#taaPublicKeyModal`) displaying the complete TAA registration public key.
   - Migrate the copy public key icon button (`#copyPubKeyBtn`) into the modal window header, retaining the copy-to-clipboard functionality and visual feedback.

3. **Side-by-Side ID Input Fields & Left-Aligned Randomize Button**:
   - In both the Model Dispatch card (`#card-importModel`) and Data Dispatch / Result Report card (`#card-import`), display `requestId` and `taskId` input fields side-by-side.
   - Position the "随机 ID" (Random ID) button to the left of the side-by-side input fields, aligned cleanly with the text inputs.
   - Remove the redundant "随机 ID" button from the bottom actions row of both cards.

## 3. Architecture & Component Design

### 3.1 Template Layout (`index.html`)
- Remove `<nav class="pipeline-stepper" id="pipelineStepper">...</nav>`.
- In `#card-attestation`:
  - Add `<button type="button" id="taaPublicKeyBtn" class="secondary" onclick="openTaaPublicKeyModal()" disabled>公钥</button>` in the header action group.
  - Remove `#registerPublicKeyBox` from the card body.
- Add `<div id="taaPublicKeyModal" class="modal-overlay">` containing the modal header, copy button `#copyPubKeyBtn`, close button, and `<textarea id="registerPublicKey">`.
- In `#card-importModel` and `#card-import`:
  - Wrap the randomize button and side-by-side input columns in `.id-input-row`.
  - Place `.btn-field-random` as the first child on the left.
  - Place `.id-inputs-cols` with two `.id-input-col` elements containing `requestId` and `taskId` fields.
  - Keep only primary action buttons in the bottom `.actions` container.

### 3.2 CSS Styling (`components.css`)
- Define `.id-input-row` with flexbox, `align-items: flex-end`, and responsive column layout.
- Style `.btn-field-random` with matching height (35px) and flex-shrink protection.
- Ensure `.id-inputs-cols` and `.id-input-col` flex-shrink properly with appropriate label margins.

### 3.3 JavaScript Logic (`app.js`, `drawer.js`, `crypto.js`)
- Update `renderRegister(data)` to control `#taaPublicKeyBtn` disabled state based on public key availability.
- Implement `openTaaPublicKeyModal()` and `closeTaaPublicKeyModal()` with Escape key listener support.
- Protect `syncStepperState(res)` with null-checks so removing stepper elements causes no runtime exceptions.
