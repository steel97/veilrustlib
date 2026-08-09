//! The `/getcoins` slash command.
//!
//! Port of `ref/veil-faucet/lib/commands/get_coins_command.dart`, including its
//! two-stage rate limit: the queue is checked before the modal opens and again
//! after the address comes back, so a user cannot open two modals at once and
//! queue twice.

use std::sync::Arc;
use std::time::Duration;

use serenity::builder::{
    CreateCommand, CreateInteractionResponse, CreateInteractionResponseMessage,
};
use serenity::client::Context;
use serenity::model::application::CommandInteraction;
use serenity::utils::CreateQuickModal;

use crate::config::Config;
use crate::db::Queue;
use crate::error::FaucetError;
use crate::util::{format_wait, unix_timestamp};

/// Command name, matching the Dart bot so existing users see no change.
pub const COMMAND_NAME: &str = "getcoins";

/// Command description, likewise unchanged.
const COMMAND_DESCRIPTION: &str = "get some veil";

/// How long the modal waits for the user before giving up.
///
/// The Dart bot had no timeout, which leaks a pending interaction whenever a user
/// dismisses the dialog.
const MODAL_TIMEOUT: Duration = Duration::from_secs(600);

/// The command's definition, for registration.
pub fn definition() -> CreateCommand {
    CreateCommand::new(COMMAND_NAME).description(COMMAND_DESCRIPTION)
}

/// Handle one `/getcoins` invocation.
pub async fn handle(
    ctx: &Context,
    interaction: &CommandInteraction,
    config: &Config,
    queue: &Arc<Queue>,
) -> Result<(), FaucetError> {
    let user_id = interaction.user.id.to_string();
    let now = unix_timestamp();

    // First rate-limit check, before bothering the user with a dialog.
    if let Some(ready_at) = queue
        .next_allowed_request(&user_id, config.timestamp_limit_secs(), now)
        .await?
    {
        reply(ctx, interaction, too_early_message(ready_at, now)).await?;
        return Ok(());
    }

    let modal = CreateQuickModal::new("Type in your address")
        .timeout(MODAL_TIMEOUT)
        .short_field("Wallet address bv/sv");

    let Some(response) = interaction.quick_modal(ctx, modal).await? else {
        // The user dismissed the dialog or the timeout elapsed. Nothing was
        // queued, so there is nothing to undo.
        return Ok(());
    };

    let address = response
        .inputs
        .first()
        .map(|value| value.trim().to_string())
        .unwrap_or_default();

    // Validate before touching the queue, so a bad address is never stored.
    // classify_address accepts both families the modal asks for: sv1 stealth
    // addresses and bv/V basecoin addresses.
    if veilrustlib::classify_address(&address).is_err() {
        respond_to_modal(
            ctx,
            &response.interaction,
            "Specified address seems to be invalid, please try again!",
        )
        .await?;

        return Ok(());
    }

    // Second rate-limit check. Time passed while the modal was open, and the
    // user may have queued through another modal in the meantime.
    let now = unix_timestamp();

    if let Some(ready_at) = queue
        .next_allowed_request(&user_id, config.timestamp_limit_secs(), now)
        .await?
    {
        respond_to_modal(ctx, &response.interaction, too_early_message(ready_at, now)).await?;
        return Ok(());
    }

    let message = match queue.enqueue(&address, &user_id, now).await {
        Ok(()) => match queue.pending_count().await {
            Ok(size) => format!("You successfully added to queue! Queue size: {size}"),
            // The request is queued either way; only the count is unknown.
            Err(error) => {
                eprintln!("Could not read the queue size: {error}");
                "You successfully added to queue!".to_string()
            }
        },
        Err(error) => {
            eprintln!("Could not queue a request for user {user_id}: {error}");
            "Failed to add user to queue!".to_string()
        }
    };

    respond_to_modal(ctx, &response.interaction, message).await?;

    Ok(())
}

/// The "too early" reply, reporting how long is left.
fn too_early_message(ready_at: i64, now: i64) -> String {
    format!(
        "Too early! You can request free coins after {}",
        format_wait(ready_at.saturating_sub(now))
    )
}

/// Reply to the initial command interaction.
async fn reply(
    ctx: &Context,
    interaction: &CommandInteraction,
    content: impl Into<String>,
) -> Result<(), FaucetError> {
    let message = CreateInteractionResponseMessage::new()
        .content(content)
        .ephemeral(true);

    interaction
        .create_response(&ctx.http, CreateInteractionResponse::Message(message))
        .await?;

    Ok(())
}

/// Reply to the modal submission.
///
/// A modal submission needs its own response, otherwise Discord shows the user
/// an "interaction failed" error even though the request was queued.
async fn respond_to_modal(
    ctx: &Context,
    interaction: &serenity::model::application::ModalInteraction,
    content: impl Into<String>,
) -> Result<(), FaucetError> {
    let message = CreateInteractionResponseMessage::new()
        .content(content)
        .ephemeral(true);

    interaction
        .create_response(&ctx.http, CreateInteractionResponse::Message(message))
        .await?;

    Ok(())
}
