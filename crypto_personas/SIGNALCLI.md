
# Signal-CLI Setup for Staging Environment

This guide explains how to build `signal-cli` from source and configure it to use a **staging account** on the Signal network.

---

## 🛠 Building `signal-cli` from Source

### 1. Clone the Repository

```bash
git clone https://github.com/AsamK/signal-cli.git
cd signal-cli
```

### 2. Build the Project

Use the provided Gradle wrapper (or `gradle` if already installed):

```bash
./gradlew build
```

### 3. Optional Build Targets

Depending on your needs, you may also want to run:

- **Install shell wrapper:**
  ```bash
  ./gradlew installDist
  ```
  This creates a script at `build/install/signal-cli/bin/signal-cli`.

- **Create tarball:**
  ```bash
  ./gradlew distTar
  ```

- **Create fat JAR (all dependencies bundled):**
  ```bash
  ./gradlew fatJar
  ```

- **Run CLI directly:**
  ```bash
  ./gradlew run --args="--help"
  ```

---

## 📱 Set Up Signal Staging Account with `signal-cli`

Signal provides a **staging environment** for development and testing. Follow these steps to register a phone number with the staging server.

---

### Step 1: Generate a CAPTCHA URL

1. Visit [https://signalcaptchas.org/staging/registration/generate.html](https://signalcaptchas.org/staging/registration/generate.html).
2. Click the **"I am human"** CAPTCHA checkbox.
3. When prompted to open Electron, click **"Cancel"**.
4. Below the CAPTCHA, click **"Open Signal"**, then right-click it and select **"Copy Link"**.
5. This copied link is your CAPTCHA URL.

---

### Step 2: Register the Account

```bash
signal-cli --service-environment staging -u +[account number] register --captcha [captcha url]
```

**Important Notes:**
- The account number **must** include the country code.
  - ✅ Correct: `+19995551234`
  - ❌ Incorrect: `999-555-1234` or `+1 999-555-1234`
- Do not use spaces or dashes in the number.

---

### Step 3: Verify the Account

Once you've submitted your phone number, Signal will send you a verification code (via SMS or voice call).

Use the following command to verify:

```bash
signal-cli --service-environment staging -u +[account number] verify [verification code]
```

After successful verification, your number is registered on the Signal staging environment and ready for testing.

---

## ✅ You're Done!

You now have a fully functional Signal staging account registered via `signal-cli`. You can now send messages, create groups, and test features in an isolated environment.


## Verify Your Signal Staging Account

After you have successfully registered and verified your account, you can confirm that your account is properly set up using the following command:

```bash
signal-cli --service-environment staging listAccounts
```

This command should list the account you registered, confirming that it is correctly linked to the staging environment.

## Create and Join a Testing Group

To create a new testing group and add your registered and verified account(s) to the group, run the following command:

```bash
signal-cli --service-environment staging \
  -a [account number] \
  updateGroup \
  -n [YOUR_GROUP_NAME] \
  -m [account number [account number] ...] \
  --admin [account number  [account number] ...] \
  --link enabled \
  --set-permission-add-member every-member \
  --set-permission-edit-details every-member \
  --set-permission-send-messages every-member \

```

Be sure to replace `[account number]` with your full phone number(s), including the country code (e.g., `+19995551234` for a US number).

This will add your account to the Signal group used for testing in the staging environment.


