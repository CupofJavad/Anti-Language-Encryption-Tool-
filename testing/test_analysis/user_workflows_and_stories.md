# User Workflows and User Stories - Forgotten-E2EE Web Application

## Document Purpose
This document identifies ALL user workflows and user stories in the application to enable comprehensive user-focused testing.

---

## User Workflows

### Workflow 1: Key Generation (Primary)
**Path**: Main Interface → Generate Keys Tab → Enter Name → Click "Generate Keys" → View Results

**Steps**:
1. User navigates to main interface (`/`)
2. User sees "Generate Keys" tab (active by default)
3. User enters a name in the name field (default: "Alice")
4. User clicks "Generate Keys" button
5. System displays "Generating keys..." message
6. System calls `/api/keygen` endpoint
7. System displays public key and secret key in formatted boxes
8. User can copy keys from the display

**Variations**:
- User leaves name empty (should default to "Anonymous")
- User enters special characters in name
- User enters very long name
- User clicks button multiple times rapidly
- Network fails during key generation
- User navigates away during generation

---

### Workflow 2: Encryption (Primary)
**Path**: Main Interface → Encrypt Tab → Enter Public Key → Enter Message → (Optional) Check Armor → Click "Encrypt" → View Result

**Steps**:
1. User navigates to main interface
2. User clicks "Encrypt" tab
3. User pastes recipient's public key into textarea
4. User enters message to encrypt
5. User optionally checks "Use steganographic armor" checkbox
6. User clicks "Encrypt" button
7. System displays "Encrypting..." message
8. System calls `/api/encrypt` endpoint
9. System displays encrypted output (binary or armor format)
10. User can copy encrypted message

**Variations**:
- User encrypts without public key
- User encrypts with invalid public key format
- User encrypts with empty message
- User encrypts with very long message
- User encrypts with special characters/Unicode
- User encrypts with armor enabled but lexicon missing
- User encrypts with corrupted public key JSON
- User encrypts with public key from different version
- Network fails during encryption
- User switches tabs during encryption

---

### Workflow 3: Decryption (Primary)
**Path**: Main Interface → Decrypt Tab → Enter Secret Key → Enter Encrypted Message → Click "Decrypt" → View Plaintext

**Steps**:
1. User navigates to main interface
2. User clicks "Decrypt" tab
3. User pastes their secret key into textarea
4. User pastes encrypted message into textarea
5. User clicks "Decrypt" button
6. System displays "Decrypting..." message
7. System calls `/api/decrypt` endpoint
8. System displays decrypted plaintext
9. User can copy decrypted message

**Variations**:
- User decrypts without secret key
- User decrypts without encrypted message
- User decrypts with invalid secret key format
- User decrypts with invalid encrypted message format
- User decrypts message encrypted for different recipient
- User decrypts corrupted encrypted message
- User decrypts armor format without lexicon
- User decrypts binary format
- User decrypts armor format
- User decrypts message with wrong secret key
- Network fails during decryption
- User switches tabs during decryption

---

### Workflow 4: Complete Encryption/Decryption Cycle
**Path**: Generate Keys → Copy Public Key → Switch to Encrypt → Paste Public Key → Enter Message → Encrypt → Copy Encrypted → Switch to Decrypt → Paste Secret Key → Paste Encrypted → Decrypt → Verify Plaintext

**Steps**:
1. User generates keys (Workflow 1)
2. User copies public key
3. User switches to Encrypt tab
4. User pastes public key
5. User enters message
6. User encrypts message
7. User copies encrypted output
8. User switches to Decrypt tab
9. User pastes secret key
10. User pastes encrypted message
11. User decrypts
12. User verifies plaintext matches original

**Variations**:
- User uses different browser/device for encryption and decryption
- User uses keys generated in different session
- User encrypts multiple messages with same keypair
- User decrypts multiple messages with same keypair

---

### Workflow 5: Tab Navigation
**Path**: Any Tab → Click Different Tab → View New Tab Content

**Steps**:
1. User is on any tab (Generate Keys, Encrypt, or Decrypt)
2. User clicks a different tab button
3. Previous tab content hides
4. New tab content displays
5. Active tab button is highlighted

**Variations**:
- User rapidly switches between tabs
- User switches tabs during API call
- User switches tabs with form data entered
- User uses keyboard navigation
- User uses browser back/forward buttons

---

### Workflow 6: Embed Page Usage
**Path**: Navigate to `/embed` → Use Simplified Interface

**Steps**:
1. User navigates to `/embed` URL
2. User sees simplified interface with all functions on one page
3. User can generate keys, encrypt, and decrypt without tab switching
4. All functionality works same as main interface

**Variations**:
- User embeds page in iframe
- User uses embed page on mobile device
- User uses embed page with different screen sizes
- User shares embed page URL

---

### Workflow 7: Error Recovery
**Path**: Error Occurs → User Sees Error Message → User Corrects Input → User Retries

**Steps**:
1. User performs action that causes error
2. System displays error message in red box
3. User reads error message
4. User identifies problem (missing field, invalid format, etc.)
5. User corrects input
6. User retries action
7. Action succeeds

**Variations**:
- User ignores error and tries different action
- User refreshes page after error
- User clears all fields after error
- Multiple errors occur in sequence

---

### Workflow 8: Copy/Paste Operations
**Path**: Generate/Encrypt/Decrypt → Copy Output → Paste into Different Field or External Application

**Steps**:
1. User performs action that produces output (keys, encrypted message, plaintext)
2. User selects output text
3. User copies to clipboard (Ctrl+C / Cmd+C)
4. User navigates to different field or application
5. User pastes content (Ctrl+V / Cmd+V)
6. Content is correctly pasted

**Variations**:
- User copies partial text
- User copies from one field and pastes to another
- User copies and pastes between browser tabs
- User copies and pastes to external text editor
- User uses right-click context menu
- User uses keyboard shortcuts
- Clipboard contains invalid data

---

### Workflow 9: Form Input and Validation
**Path**: User Enters Data → System Validates → User Submits

**Steps**:
1. User focuses on input field
2. User types or pastes data
3. System may validate in real-time (if implemented)
4. User clicks submit button
5. System validates data
6. System processes or shows error

**Variations**:
- User enters data and deletes it
- User enters data and modifies it
- User enters data with leading/trailing whitespace
- User enters data with newlines
- User enters data with special characters
- User enters very long data
- User enters empty data
- User uses autofill
- User uses browser spell-check

---

### Workflow 10: Network Error Handling
**Path**: User Action → Network Request → Network Fails → Error Displayed

**Steps**:
1. User performs action requiring network request
2. System initiates API call
3. Network fails (timeout, connection error, server error)
4. System catches error
5. System displays user-friendly error message
6. User can retry action

**Variations**:
- Network timeout
- Connection refused
- Server returns 500 error
- Server returns 400 error
- Server returns 404 error
- Slow network connection
- Intermittent network failures
- User goes offline during request

---

## User Stories

### Story 1: First-Time User - Key Generation
**As a** first-time user  
**I want to** generate my encryption keys  
**So that** I can start using the encryption service

**Acceptance Criteria**:
- User can access the key generation interface
- User can enter a name (or leave it empty)
- User can generate keys with one click
- User receives both public and secret keys
- Keys are displayed in a readable format
- User can copy keys easily

---

### Story 2: Regular User - Encrypting a Message
**As a** regular user  
**I want to** encrypt a message for a recipient  
**So that** only they can read it

**Acceptance Criteria**:
- User can paste recipient's public key
- User can enter message to encrypt
- User can choose armor or binary format
- User receives encrypted output
- Encrypted output can be copied
- Error messages are clear if something goes wrong

---

### Story 3: Regular User - Decrypting a Message
**As a** regular user  
**I want to** decrypt a message sent to me  
**So that** I can read the original content

**Acceptance Criteria**:
- User can paste their secret key
- User can paste encrypted message
- User can decrypt and see plaintext
- Error messages are clear if decryption fails
- User can copy decrypted message

---

### Story 4: Power User - Complete Workflow
**As a** power user  
**I want to** generate keys, encrypt, and decrypt in one session  
**So that** I can test the full functionality

**Acceptance Criteria**:
- User can complete full cycle without errors
- Keys generated work for encryption/decryption
- Encrypted messages decrypt correctly
- Plaintext matches original message

---

### Story 5: Mobile User - Responsive Design
**As a** mobile user  
**I want to** use the application on my phone  
**So that** I can encrypt/decrypt on the go

**Acceptance Criteria**:
- Interface is usable on mobile screen
- Text inputs are accessible
- Buttons are large enough to tap
- Content doesn't overflow screen
- Copy/paste works on mobile

---

### Story 6: Privacy-Conscious User - No Data Storage
**As a** privacy-conscious user  
**I want to** use the service without data being stored  
**So that** my communications remain private

**Acceptance Criteria**:
- No keys are stored on server
- No messages are stored on server
- All processing happens in memory
- No tracking or logging of user data

---

### Story 7: Technical User - API Access
**As a** technical user  
**I want to** use the API directly  
**So that** I can integrate it into my own applications

**Acceptance Criteria**:
- API endpoints are documented
- API returns proper JSON responses
- API handles errors gracefully
- API supports CORS for cross-origin requests

---

### Story 8: User with Poor Network - Error Handling
**As a** user with poor network  
**I want to** see clear error messages when requests fail  
**So that** I know what went wrong and can retry

**Acceptance Criteria**:
- Network errors are clearly displayed
- User can retry failed operations
- No data is lost during network failures
- Timeout errors are handled gracefully

---

### Story 9: User Making Mistakes - Input Validation
**As a** user who might make mistakes  
**I want to** see clear validation errors  
**So that** I can correct my input

**Acceptance Criteria**:
- Missing required fields show errors
- Invalid formats show specific errors
- Error messages are actionable
- User can correct errors and retry

---

### Story 10: User Sharing Keys - Copy/Paste
**As a** user sharing keys with others  
**I want to** easily copy and paste keys  
**So that** I can share them via other channels

**Acceptance Criteria**:
- Keys can be easily selected
- Keys can be copied to clipboard
- Keys can be pasted into other applications
- Keys maintain format when copied/pasted

---

## Edge Cases and Error Scenarios

### Input Edge Cases
- Empty strings
- Very long strings (100KB+)
- Special characters (Unicode, emojis, control characters)
- Whitespace-only strings
- Strings with newlines
- Malformed JSON
- Invalid base64
- Wrong key types (public vs secret)
- Keys from different versions
- Corrupted keys

### Network Edge Cases
- Request timeout
- Connection refused
- Server 500 errors
- Server 400 errors
- Server 404 errors
- Slow responses
- Intermittent failures
- CORS errors
- Network unavailable

### Browser Edge Cases
- Old browsers
- Mobile browsers
- Different screen sizes
- JavaScript disabled
- Cookies disabled
- Local storage disabled
- Pop-up blockers
- Ad blockers interfering

### User Behavior Edge Cases
- Rapid clicking
- Multiple simultaneous requests
- Navigating away during operation
- Refreshing page during operation
- Using browser back/forward
- Opening multiple tabs
- Copying partial data
- Pasting invalid data
- Clearing fields during operation

---

## Summary

**Total Workflows Identified**: 10  
**Total User Stories Identified**: 10  
**Total Edge Cases Identified**: 30+  

This comprehensive mapping enables creation of 50+ user-focused error tests covering all scenarios where users might encounter problems.

