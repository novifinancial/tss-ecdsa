# Contributing to `tss-ecdsa`

If you find an error, please submit an issue describing the problem and expected behavior.

## Code of Conduct
Please be kind, courteous, and respectful. This project, although not formally affiliated with the Rust project, supports the Rust Code of Conduct. Please report any violations of this code of conduct to conduct@boltlabs.io.

## Development Workflow
Our main development happens in the `main` branch.
Workflows start with epics and/or issues. If you want to write code, its purpose should first be captured in an appropriate issue.

### Writing issues

Before taking on a new issue, it is important to make sure that the issues being made are clear and outline a specific task. Below are some helpful criteria for what makes a well-defined issue:

1. Use informative and concise titles. A developer should be able to understand the high-level purpose of the ticket from the title.

1. State the problem. Make sure to provide sufficient context for a developer to be able to understand the ticket requirements. The issue description should go into some detail about the issue, bug, or feature and be as descriptive as possible. If the ticket is a bug, include sufficient instructions for reproducibility.

1. Use labels as appropriate. Please browse through the available labels and pick those that seem most appropriate.

1. As part of context, it may be helpful to link to design specification documents, PRs, or other issues. (However, if a repository is public, be sure to link only to publicly available resources.)

1. Issues must list criteria for closing e.g:
- What functionality/logic must exist for the problem described to be solved or addressed?

- Are there any issues that should be made as a product of this issue?

- What tests need to be written as part of this issue?

- Issues must be tagged with the appropriate epic(s).

### Working on issues

1. Develop in a branch (internal contributors) or in a fork (external contributors). Keeping development in a branch or fork allows the `main` branch to remain stable.

1. Commits should be linked to issues. Even if the commit seems “small”, there should be an associated issue.

1. Add comments to commits. Whenever pushing a commit to a repository, it is important to include a descriptive comment to provide additional context about the contents. The commit message should link to the issue that the commit addresses (e.g. #44).

1. Do not commit local config files into source control. It’s not a good idea to commit local config files to version control. Usually, those are private configuration files you don’t want to push to remote because they are holding secrets, personal preferences, history, or general information that should stay only in your local environment. Add such files to the .gitignore file so you don’t accidentally commit.

1. Create a PR. After the feature is completed in the branch, you can create a pull request to allow others to review before merging into the `main` branch. Repositories should include continuous integration to maintain the integrity of the `main` branch.

1. Keep your branch up to date with `main`. When a branch is out of sync with `main`, it can lead to a bunch of merge conflicts when syncing. The best practice is to ensure that you're consistently rebasing your current branch onto the `main` branch as you work, especially if it is a long-outstanding branch. The only exception: when your work is being reviewed in a PR, rebasing can make it more difficult to track comments and changes. Wait until the PR is approved.

1. Avoid using git merge when syncing with the upstream `main` branch. A git merge typically pollutes the git history and should be avoided. Instead, do a rebase (via git rebase origin) to cleanly apply local changes to upstream commits.

1. You may want to squash your commits together with git rebase, or your IDE may have support for easily squashing commits.

1. After merging into `main`, delete your (now-stale) branch. Every time one branch is merged into another, the branch that is merged in becomes stale (if there isn't any further work being done). Delete the branch; Github typically allows you to safely restore the branch later if needed.

### Submitting and Reviewing PRs

Once you, as the developer, have worked on a well-defined issue or set of issues (as described above), you can use the following list of criteria to see if your code is ready for review. The PR reviewer, who should be a different person from the developer, can use the same list for their review as well.

Aside from checking that the general functionality and logic of the code addresses the issue(s) at hand, you and the reviewer should check that:

1. The PR has a comprehensive description of its purpose and uses closing keywords to automatically link issues to the PR.

1. The developer has rebased with `main` before marking the code as ready for review. This is to make sure the code is as up-to-date as possible and to make merging easier after the review.

1. All "checks" pass. This repo's Github actions runs a formatting check (rustfmt), a linting check (clippy), and runs all unit and integration tests in the repo. It may be helpful, as the developer, to make a draft PR so that Github can run these checks for you instead of having to run them locally.

1. The code is readable and self-explanatory for the reader, and there are comments where appropriate to provide clarity.

1. All APIs are documented.

1. Commit messages are linked with the relevant issues number(s).

1. The new code has testing infrastructure - this includes appropriate unit tests and/or integration tests, and issues to describe plans for creating any testing infrastructure that could not be included in the PR.

1. Any TODOs left in the code are marked with an associated issue number to an issue that is defined using the above criteria.

1. Your commits have been squashed together into a single commit. (In rare cases, multiple commits may be appropriate).

If you believe the above criteria have been met, go ahead mark your PR as ready for review.

### Definition of Done

An issue is done after:

1. The developer thinks the associated PR passes the above criteria and marks the PR as ready for review.

1. The PR reviewer approves the code using the same criteria.

1. The developer rebases their branch with `main` again to catch any changes that may have happened during the review period.

1. The developer merges their PR branch into `main` (or whichever branch they initially branched from). This should also close any relevant issues from the PR and delete the PR branch.

## Logging
This library supports logging using the [`tracing`](https://docs.rs/tracing/latest/tracing/)
crate.

### Main `tracing` Concepts.
We utilize the following concept from `tracing`:
- **Events**: These are the individual logging events that are called as our program executes. Events have an info level attached to them. You may create a new event by using the appropriate event macro from `tracing`, e.g:
```
info!("This is a logging event!");
```
You may add runtime values to our events as well:
```
debug!(
    "processing participant: {}, with message type: {:?} from {}",
     &participant.id,
     &message.message_type(),
    &message.from(),
    );
```
This uses the same syntax as Rust string formatting.

- **Spans** represent logical regions of code, usually a function. All _event_s within a span will have additional span data attached to the event. This allows us to add context-relevant data to an event without having to explicitly add this data
  to our event. For example an event like `info!("Processing auxinfo message!")` within our spans will look like:
```
  2023-02-07T06:17:56.549284Z  INFO tss_ecdsa::auxinfo::participant: Handling auxinfo ready message.
    at src/auxinfo/participant.rs:124
    in tss_ecdsa::auxinfo::participant::handle_ready_msg with Message { message_type: Auxinfo(Ready), identifier: Id(69c21b05), from: ParticipantIdentifier(Id(95b1d9de)), to: ParticipantIdentifier(Id(2470af1b)) }
    in tss_ecdsa::auxinfo::participant::process_message with Message { message_type: Auxinfo(Ready), identifier: Id(69c21b05), from: ParticipantIdentifier(Id(95b1d9de)), to: ParticipantIdentifier(Id(2470af1b)) }
    in tss_ecdsa::protocol::process_single_message with Message { message_type: Auxinfo(Ready), identifier: Id(69c21b05), from: ParticipantIdentifier(Id(95b1d9de)), to: ParticipantIdentifier(Id(2470af1b)) }
```
This event has multiple spans attached. Such as: `handle_ready_msg`, `process_message`, and `process_single_message`. These spans allow us to understand the function call chain at a high-level. Additionally, spans
may contain _fields_. These fields attached relevant data to all events within our span. In the log message above, we see our span has a single field `Message`. So `tracing` attached the `Debug` output of `Message` to the event.

#### Adding your Own Span.
The best way to create your own span is using the
[`instrument`](https://docs.rs/tracing/0.1.37/tracing/attr.instrument.html) macro. This macro
will automatically create a new span when the instrumented function is
called. This span will have the name of the function and the module path as
the `target` (this can be used for filtering by certain targets).

Please follow the following template for instrumenting your function with
spans:
```text
#[instrument(skip(sensitive_arg), err(Debug))]
fn foo(arg1: _, arg2: _, sensitive_arg: SuperSecret) -> _ {}
```
By default, `instrument` will create a new span where every argument to a
function is a span field. *This is not desirable for this library as we
want to avoid logging sensitive data!* Make sure to skip sensitive arguments
with the `skip(sensitive_arg_1, sensitive_arg_2, ...)` option. You can also use
the `skip_all` option if none of the function arguments need to be logged.

Finally, the `err(Debug)` option tells `tracing` that any `Result::Err(_)`
returned from this function should be logged as events (with the default
level of `error`). This is useful for logging where errors originated from in
our code. The `Debug` part tells tracing to use the `Debug` implementation
of this type for formatting, instead of the default `Display`.

Note that by default, return values of functions are not recorded. You can
add the `ret` option to `instrument` if you wish to record the Ok(_) return
value as a field.

`tracing` relies on the `Debug` implementation of types for printing values.
Your type must implement `Debug` if you wish to include it as a field.

#### Which Arguments Should be Recorded as Fields?
In general, we should only include fields for our span that provide
important information that should be attached to every event that happens
within that span.

Fields are useful for attaching data to every event without having to
explicitly pass that data as arguments to functions.

Note: *We should be careful to avoid recording any sensitive data as
fields!*

#### Which Function Should be `instrument`ed?
We want to instrument functions which either:
1) Logically represent an important step in our library.
2) Record useful fields to be attached to event within that span.
3) Have return values which are useful to log.

Instrumenting multiple functions which call each other will create a useful
"backtrace-like" context which allows us to understand the calling context
of an event. For example:
```text
  2022-12-06T18:57:39.669808Z  INFO
lock_keeper_key_server::operations::authenticate: Starting authentication protocol.
    at lock-keeper-key-server/src/operations/authenticate.rs:38
    in lock_keeper_key_server::operations::authenticate::operation
    in lock_keeper_key_server::server::operation::handle_request with request_id: "52ad8008-1eb9-4ad5-8bce-0344a958fd1e", action: "Authenticate"
```
We want to avoid instrumenting uninteresting functions, e.g. functions which
represent an implementation detail instead of a logical step in our library's
execution.

### Logging Levels
So far our logging documentation has focused on the default tracing level of
`INFO`. Events may be added for the following tracing levels: `error`,
`warn`, `info`, `debug`, and `trace`. Here we give a brief overview of what
falls under every level:
- **error**: Report unexpected errors or failures in the system.
- **warn**: Warn of unexpected errors, unforeseen program states, or
  possible issues that are not necessarily fatal, but should be logged so
  they may be debugged later.
- **info**: For high-level, relevant, events to the execution of the code.
  This is our default
  logging level and should produce useful messages for developers.
- **debug**: More verbose, good to have information for debugging purposes.
- **trace**: Very verbose information that allows you to trace the execution
  of a program at fine granularity, e.g. program control flow.
