

<!-- 

This project allows anonymous and pseudonymous messaging in Signal groups by acting as a proxy between [Axum](https://github.com/tokio-rs/axum) and the [Signal-CLI JSON-RPC daemon](https://github.com/AsamK/signal-cli). A custom CLI binary is used to interface with the Axum server, enabling anonymous group messaging, polls, reactions, and more—all built on top of cryptographically enforced workflows.

---

## ✅ Prerequisites

Make sure you have:

- [`signal-cli`](https://github.com/AsamK/signal-cli) installed (used in daemon mode)
- A Signal number registered
- `cargo` (Rust) installed
- A Signal group already created

For Signal setup steps (e.g. linking a device, creating a group), see [`SIGNALCLI.md`](./SIGNALCLI.md).

---

## ⚙️ Setup

Create a `.env` file with the following:

```bash
SIGNAL_BOT_NUMBER=
```

Make sure the phone number you provide is the acting "phantom" bot account for which you will send messages from crypto personas under. This should be in the format +[COUNTRY_CODE][PHONE_NUMBER] with no dashes. 

**Important Notes:**
- The account number **must** include the country code.
  - ✅ Correct: `+19995551234`
  - ❌ Incorrect: `999-555-1234` or `+1 999-555-1234`
- Do not use spaces or dashes in the number.

---

## 🖥 Running the System

You need **three terminals**:

---

### **Terminal 1: Start the Signal-CLI Daemon**

```bash
signal-cli --service-environment staging daemon --tcp 127.0.0.1:7583
```

This must be running first.

---

### **Build and Install the CLI Tool**

Run the following command to build the project and make the binary globally accessible (temporarily for your current terminal session):

```bash
cargo build --release && \
export PATH="$PATH:$(pwd)/target/release" && \
source ~/.zshrc
```

> 💡 **Note:** The `export PATH=...` part temporarily adds the binary to your `PATH`. If you want it to persist across terminal sessions, add this line to your `~/.zshrc` file manually:
>
> ```bash
> export PATH="$PATH:/full/path/to/your/project/target/release"
> ```
> Then run:
> ```bash
> source ~/.zshrc
> ```


### **Terminal 2: Run the Axum Server**

```bash
cd axum-signal-cli/
cargo build --release
```

Add your CLI binary to your `$PATH`:

```bash
echo 'export PATH="$PATH:$(pwd)/target/release"' >> ~/.zshrc
source ~/.zshrc
```

```bash
cargo run --bin server --release
```

The server listens for incoming client commands and communicates with the Signal daemon.

---

### **Terminal 3: Use the Custom CLI to run the Client and Send Anonymous Messages**

```bash
cd axum-signal-cli/
```

Add your CLI binary to your `$PATH`:

```bash
echo 'export PATH="$PATH:$(pwd)/target/release"' >> ~/.zshrc
source ~/.zshrc
```

Then you can use the CLI directly:

```bash
client join             # Join as an anonymous user
client post -m "Hi" -g "GROUP_ID"
```

---

## 🧭 Usage Workflow

1. Start the **Signal daemon**.
2. Start the **Axum server**.
3. In a third terminal:
   - Run `client join` to anonymously join a Signal group.
   - Post messages, create polls, and vote using other CLI commands.

---



## ✅ Tips

- You can get your group ID using `signal-cli listGroups`.
- Timestamps for messages are UNIX epoch seconds (provided in the metadata of group messages).
- Use `pseudo-index` before posting pseudonymously.
- The system does **not** require Signal group members to be running this server—only you need the setup for anonymous participation.

---

## 🛠 Development Notes

- All anonymous logic runs through the Axum server which proxies to the Signal daemon.
- Cryptographic logic for anonymity, pseudonymity, and ZK workflows is implemented within Rust (see `src/zk/`).



Perfect — below is **clean GitHub-ready Markdown**. You can copy/paste this directly into a `README.md` file. No extra formatting, no UI blocks, just pure Markdown.

---

```markdown -->
# crypto_personas

`crypto_personas` enables **anonymous and pseudonymous messaging** across communication platforms using cryptographic workflows and zero-knowledge enforcement.

The system currently supports:

- 📱 Signal
- 💬 Slack

It operates as a proxy between messaging platforms and an Axum server, while a custom CLI tool enables anonymity, pseudonymity, voting, reputation tracking, and moderation.

---

# 📦 Platform Support

- **Signal Integration**
  - Uses `signal-cli` JSON-RPC daemon
- **Slack Integration**
  - Uses Slack Developer APIs with Socket Mode

---

# ✅ General Prerequisites

You must have:

- Rust + Cargo installed
- A Slack Developer Account (for Slack integration)
- A Signal account + `signal-cli` (for Signal integration)

---

# 💬 Slack Setup

## 1. Create Slack Developer App

Register for a Slack developer account:

https://api.slack.com/developer-program

---

## 2. Create App + Sandbox

Create:

- A new Slack App
- A Developer Sandbox Environment

Documentation:

https://docs.slack.dev/tools/developer-sandboxes/

---

## 3. Enable Socket Mode

Ensure your Slack App is connected using **Socket Mode**.

---

## 4. Configure Bot Scopes

Enable the following bot scopes:

```
channels:history
channels:join
chat:write
chat:write.customize
emoji:read
files:read
files:write
groups:history
im:history
im:write
mpim:history
mpim:write
reactions:read
reactions:write
users:write
```

---

## 5. Configure Event Subscriptions

Enable these bot event subscriptions:

```
message.channels
message.groups
message.im
message.mpim
reaction_added
reaction_removed
```

---

## 6. Add Bot to Sandbox Workspace

Add the bot to:

- Your sandbox workspace
- A designated test group chat channel

---

## 7. Environment Variables

Create:

```
crypto_personas/.env
```

Add:

```bash
SLACK_BOT_TOKEN=xoxb-YOUR-BOT-TOKEN
SLACK_APP_TOKEN=xapp-YOUR-APP-TOKEN
```

⚠️ The App Token must include the `connections:write` scope.

---

# 📱 Signal Setup

## Prerequisites

Install: [https://github.com/AsamK/signal-cli](https://github.com/AsamK/signal-cli)

Register a Signal Staging number(s) and create a group.

For full Signal setup instructions, see: `SIGNALCLI.md`

---

## Environment Variables

Create `.env`:

```bash
SIGNAL_BOT_NUMBER=+COUNTRYCODEPHONENUMBER
```

Example:

```
+19995551234
```

Do NOT include spaces or dashes.

---

# ⚙️ Building the Project

```bash
cargo build --release
```

Add the binary to your PATH:

```bash
export PATH="$PATH:$(pwd)/target/release"
source ~/.zshrc
```

To persist across sessions, add the export line to `.zshrc`.

---

# 🖥 Running the System

---

## Slack Server

```bash
cargo run --bin server --release
```

---

## Signal Daemon (Signal Only)

```bash
signal-cli --service-environment staging daemon --tcp 127.0.0.1:7583
```

---

## Client CLI

```bash
cd crypto_personas
```

Ensure binary is in PATH, then run CLI commands.


<!-- # 🧭 Slack CLI Commands

---

## Join Crypto Personas

```
slack-client join
```

---

## Anonymous Messaging

```
slack-client slack-post-anon -c [CHANNEL] -m [MESSAGE]
```

Example:

```
slack-client slack-post-anon -c "#anon" -m "Hello world"
```

---

## Pseudonymous Messaging

### Generate Pseudonym

```
slack-client gen-pseudo
```

### List Pseudonyms

```
slack-client pseudo-index
```

### Send Pseudonymous Message

```
slack-client slack-post-pseudo -c [CHANNEL] -m [MESSAGE] -i [INDEX]
```

---

## Rate-Limited Threads

### Create Thread

```
slack-client slack-new-thread -m [THREAD_MSG] -c [CHANNEL]
```

### Fetch Context

```
slack-client get-contexts
```

### Send Rate-Limited Pseudonymous Message

```
slack-client slack-post-pseudo-rate -c [CHANNEL] -m [MESSAGE] -t [THREAD] -i [INDEX]
```

---

## Polling + Voting

### Create Poll

```
slack-client slack-poll -q [QUESTION] -i [OPTION1] -j [OPTION2] -k [OPTION3] -l [OPTION4] -c [CHANNEL]
```

### Ban Poll

```
slack-client slack-ban-poll -m [OPTIONAL_MSG] -c [CHANNEL] -t [TIMESTAMP]
```

### Vote

```
slack-client slack-vote -v [VOTE_ID] -c [CHANNEL] -v [CHOICE]
```

### Poll Results

```
slack-client slack-results-poll -v [VOTE_ID] -c [CHANNEL]
```

---

## Badge System

Badge Types:

* 1 → Faculty
* 2 → Student
* 3 → Industry

### Request Badge

```
slack-client slack-request-badge -c [CHANNEL] -i [TYPE]
```

### Approve Badge (Admin)

```
slack-client approve-badge
```

### Claim Badge

```
slack-client slack-claim-badge -c [CHANNEL] -i [TYPE]
```

---

## ZK Scanning

```
slack-client scan
```

### Folding Scan

Modify:

```
crypto_personas/common/zk.rs
```

```rust
pub const NUM_SCANS_PER_FOLD: usize = 1;
```

Then run:

```
slack-client scan-folding
```

---

## Authorship Linking

```
slack-client slack-authorship -i [INDEX1] -j [INDEX2] -c [CHANNEL]
```

---

## Moderation

### Ban User

```
slack-client slack-ban -t [TIMESTAMP]
```

---

## Reactions

```
slack-client slack-reaction -c [CHANNEL_ID] -e [EMOJI] -t [TIMESTAMP]
```

---

## Reputation System

```
slack-client rep
slack-client get-rep
```

---

## Epoch Management

```
slack-client update-epoch
```

--- -->


---

## ✨ Slack CLI Command Reference

Below are all available CLI commands for Slack:

---

### `join`

Join Crypto Personas in Slack.

```bash
slack-client join
```

---

### `slack-post-anon`

Send an anonymous message to a Slack channel.

```bash
slack-client slack-post-anon -c "#channel" -m "Hello world"
```

* `-c`, `--channel`: Slack channel name
* `-m`, `--message`: Message content

---

### `gen-pseudo`

Generate a new pseudonym.

```bash
slack-client gen-pseudo
```

---

### `pseudo-index`

List all pseudonyms you have generated and their indices.

```bash
slack-client pseudo-index
```

---

### `slack-post-pseudo`

Send a pseudonymous message.

```bash
slack-client slack-post-pseudo -c "#channel" -m "Hello" -i 1
```

* `-c`, `--channel`: Slack channel name
* `-m`, `--message`: Message content
* `-i`, `--pseudo-idx`: Index of pseudonym (see `pseudo-index`)

---

### `slack-new-thread`

Create a new thread for rate-limited pseudonymous discussions.

```bash
slack-client slack-new-thread -m "Weekly Meeting" -c "#channel"
```

* `-m`, `--message`: Thread topic message
* `-c`, `--channel`: Slack channel name

---

### `get-contexts`

Fetch thread contexts from the server.
NOTE: Must be run after `slack-new-thread` before sending rate-limited pseudonymous messages.

```bash
slack-client get-contexts
```

---

### `slack-post-pseudo-rate`

Send a rate-limited pseudonymous message under a thread.

```bash
slack-client slack-post-pseudo-rate -c "#channel" -m "Hello" -t "Weekly Meeting" -i 1
```

* `-c`, `--channel`: Slack channel name
* `-m`, `--message`: Message content
* `-t`, `--thread`: Thread topic message
* `-i`, `--pseudo-idx`: Rate-limited pseudonym index

---

### `slack-poll`

Create a poll for anonymous voting.

```bash
slack-client slack-poll -q "Favorite color?" -i "Red" -j "Green" -k "Blue" -l "Purple" -c "#channel"
```

* `-q`, `--question`: Poll question
* `-i`: Option 1
* `-j`: Option 2
* `-k`: Option 3 (optional)
* `-l`: Option 4 (optional)
* `-c`, `--channel`: Slack channel name

---

### `slack-vote`

Vote in a poll.

```bash
slack-client slack-vote -v "vote_123" -c "#channel" -v "Red"
```

* `-v`, `--vote-id`: Poll identifier
* `-c`, `--channel`: Slack channel name
* `-v`, `--vote`: Selected option

---

### `slack-results-poll`

Retrieve poll results.

```bash
slack-client slack-results-poll -v "vote_123" -c "#channel"
```

* `-v`, `--vote-id`: Poll identifier
* `-c`, `--channel`: Slack channel name

---

### `slack-ban-poll`

Create a poll to vote on banning a message author.

```bash
slack-client slack-ban-poll -m "Ban user?" -c "#channel" -t "1768510420.480699"
```

* `-m`, `--message`: Optional ban poll message
* `-c`, `--channel`: Slack channel name
* `-t`, `--timestamp`: Timestamp of message containing problematic content

---

### `slack-ban`

Ban a user associated with a specific message timestamp.

```bash
slack-client slack-ban -t "1768510420.480699"
```

* `-t`, `--timestamp`: Timestamp of message

---

### `slack-request-badge`

Request a badge.

```bash
slack-client slack-request-badge -c "#channel" -i 2
```

Badge Types:

* 1 → Faculty

* 2 → Student

* 3 → Industry

* `-c`, `--channel`: Slack channel name

* `-i`: Badge index

---

### `approve-badge`

Approve a pending badge request (Admin only).

```bash
slack-client approve-badge
```

---

### `slack-claim-badge`

Claim an approved badge.

```bash
slack-client slack-claim-badge -c "CHANNEL_ID" -i 2
```

* `-c`, `--channel`: Slack channel ID (ex: C055555555) (matches `^[CGDZ][A-Z0-9]{8,}$`)
* `-i`: Badge index

---

### `scan`

Run a ZK-based scan interaction before posting.

```bash
slack-client scan
```

---

### `scan-folding`

Run a ZK-based scan interaction with folding.

```bash
slack-client scan-folding
```

#### Folding Notes

You can adjust folding batch size by modifying:

```
crypto_personas/common/zk.rs
```

```rust
pub const NUM_SCANS_PER_FOLD: usize = 1;
```

---

### `slack-authorship`

Prove two pseudonyms belong to the same user.

```bash
slack-client slack-authorship -i 1 -j 2 -c "#channel"
```

* `-i`, `--pseudo-idx1`: First pseudonym index
* `-j`, `--pseudo-idx2`: Second pseudonym index
* `-c`, `--channel`: Slack channel name

---

### `slack-reaction`

React to a Slack message.

```bash
slack-client slack-reaction -c "CHANNEL_ID" -e "👍" -t "1768510420.480699"
```

* `-c`, `--channel`: Slack channel ID (ex: C055555555) (matches `^[CGDZ][A-Z0-9]{8,}$`)
* `-e`, `--emoji`: Reaction emoji
* `-t`, `--timestamp`: Message timestamp

---

### `rep`

Update reputation scores for outstanding callbacks.

```bash
slack-client rep
```

---

### `get-rep`

Retrieve your reputation score.

```bash
slack-client get-rep
```

---

### `update-epoch`

Update the current epoch.

```bash
slack-client update-epoch
```
---


## ✨ Signal CLI Commands

Below are all the available CLI commands for Signal:

---

### `join`

Join the group anonymously.

```bash
client join
```

---

### `post`

Send an anonymous message to a group.

```bash
client post -m "testing" -g "GROUP_ID"
```

- `-m`, `--message`: Your message content
- `-g`, `--group-id`: The Signal base64 group ID

---

### `post-pseudo`

Send a message under a pseudonym you've generated.

```bash
client post-pseudo -m "hello" -g "GROUP_ID" -i 1
```

- `-i`, `--pseudo-idx`: Index of your pseudonym (see `pseudo-index`)

---

### `gen-pseudo`

Generate a new pseudonym.

```bash
client gen-pseudo
```

---

### `pseudo-index`

List all pseudonyms you've generated and their indices.

```bash
client pseudo-index
```

---

### `new-thread-ctx`

Generate a new thread for topic discussions for rate-limited pseudonym messages. NOTE: you must run `get-contexts` after running this command.

```bash
client new-thread-ctx -c "TOPIC_THREAD"
```

- `-c`: The thread for the topic discussion

---

### `get-contexts`

Get the contexts for topic threads from the server.

```bash
client get-contexts
```

---

### `post-pseudo-rate`

Send a message under a rate-limited pseudonym. NOTE: you must run `get-contexts` before running this command.

```bash
client post-pseudo-rate -m "hello" -g "GROUP_ID" -c "TOPIC_THREAD" -i 1
```

- `-i`: Index of your rate-limited pseudonym 
- `-c`: The thread for the topic discussion (see `new-thread-ctx`)

---

### `scan`

Run a ZK-based scan interaction before posting (for stronger moderation enforcement).

```bash
client scan
```

---

### `scan-folding`

Run a ZK-based scan interaction with *folding* before posting  (for stronger moderation enforcement).

```bash
client scan-folding
```


**Important Notes:**
- You can adjust the batch size for folding by changing the macro:
```bash
pub const NUM_SCANS_PER_FOLD: usize = 1;
```
This can be found in the file `crypto_personas/common/zk.rs`.
- The number of outstanding callbacks that require scanning must be at equal to or greater than the set batch size.


---

### `reaction`

React to a message in a group.

```bash
client reaction -g "GROUP_ID" -e "👍" -t 1715791234
```

- `-e`, `--emoji`: The reaction emoji 
- `-t`, `--timestamp`: Timestamp of the target message

---

### `reply`

Anonymously reply to a message.

```bash
client reply -g "GROUP_ID" -m "I agree" -t 1715791234
```

- `-t`, `--timestamp`: Timestamp of the message you wish to reply to

---

### `reply-pseudo`

Reply to a message using a pseudonym.

```bash
client reply-pseudo -g "GROUP_ID" -m "Good point" -t 1715791234 -i 1
```

- `-t`, `--timestamp`: Timestamp of the message you wish to reply to
- `-i`, `--pseudo-idx`: Index of your pseudonym (see `pseudo-index`)

---

### `poll`

Create a new poll for users to vote on.

```bash
client poll -m "Should we change topics?" -g "GROUP_ID"
```

---

### `vote`

Submit a vote (emoji) on a poll message.

```bash
client vote -g "GROUP_ID" -t 1715791234 -e "👍"
```

- `-t`, `--timestamp`: Timestamp of poll
 
---

### `count-votes`

Count votes for a given poll.

```bash
client count-votes -g "GROUP_ID" -t 1715791234
```

- `-t`, `--timestamp`: Timestamp of poll
  
---

### `ban-poll`

Start a vote to ban a message.

```bash
client ban-poll -m "Inappropriate content?" -g "GROUP_ID" -t 1715791234
```

- `-t`, `--timestamp`: Timestamp of the target message for banning

---

### `ban`

Submit a vote to ban a message.

```bash
client ban -t 1715791234
```

- `-t`, `--timestamp`: Timestamp of the target message for banning
  
---

### `rep`

Submit a reputation update on all messages with pending reputations.

```bash
client rep 
```

---

Submit a reputation update on a single message.

```bash
client single-rep -t 1715791234
```

- `-t`, `--timestamp`: Timestamp of the target message for updating reputation
  
---

### `update-epoch`

Update the current epoch.

```bash
client update-epoch
```

---

### `authorship`

Prove that two pseudonyms belong to the same user.

```bash
client authorship -i 1 -j 2 -g "GROUP_ID"
```

- `-i`, `--pseudo-idx1`: Index of your first pseudonym (see `pseudo-index`)
- `-j`, `--pseudo-idx1`: Index of your second pseudonym (see `pseudo-index`)

---

### `badge`

Claim that you have a specific badge (one of 3 badges).

```bash
client badge -i 1 -b "Faculty" -g "GROUP_ID"
```
- `-i`: Badge Index (i.e. 1, 2, or 3) 
- `-b`: Badge claimed string (default = "0")

---



## Tips

* Use `signal-cli listGroups` to get group IDs.
* Message timestamps use UNIX epoch time.
* Signal group members do NOT need to run the server.

---

# 🛠 Development Notes

* All anonymity and pseudonym logic is enforced through Rust cryptographic workflows.
* The Axum server acts as the bridge between messaging platforms.
* ZK proof workflows live in:

```
common/src/zk.rs
```

---

# 👩‍💻 Demo

After starting required services, test Slack and Signal functionality using the CLI commands above.




