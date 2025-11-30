// Leptos Password Vault Frontend

mod vault;
mod crypto;
mod password_generator;
mod storage_wasm;
mod components;
use storage_wasm as storage;

pub use vault::{Vault, Credential};
pub use crypto::SecureString;
pub use password_generator::{PasswordGenerator, PasswordOptions, PasswordStrength};

//Leptos imports
use leptos::*;
use leptos_meta::*;
use wasm_bindgen::prelude::*;

// Import components
pub use components::*;


// Application State
#[derive(Clone, Debug)]
pub enum AppState {
    Locked,
    Unlocked {
        credentials: Vec<Credential>,
    },
}

//Main App
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    
    let (app_state, set_app_state) = create_signal(AppState::Locked);
    let (vault, set_vault) = create_signal::<Option<Vault>>(None);
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (success_message, set_success_message) = create_signal::<Option<String>>(None);

    //Initialize vault on mount
    create_effect(move |_| {
        match Vault::new() {
            Ok(v) => set_vault.set(Some(v)),
            Err(e) => set_error_message.set(Some(format!("Failed to initialize vault: {}", e))),
        }
    });

    //Clear error messages after 3 seconds
    create_effect(move |_| {
        if error_message.get().is_some() {
            set_timeout(
                move || set_error_message.set(None),
                std::time::Duration::from_secs(3),
            );
        }
    });

    //Clear success messages after 3 seconds
    create_effect(move |_| {
        if success_message.get().is_some() {
            set_timeout(
                move || set_success_message.set(None),
                std::time::Duration::from_secs(3),
            );
        }
    });

    view! {
        <Stylesheet id="leptos" href="/style.css"/>
        <Title text="Secure Password Vault"/>
        
        <div class="app-container">
            <header class="app-header">
                <h1>"Secure Password Vault"</h1>
                <p class="subtitle">"Rust-powered encryption for your passwords"</p>
            </header>

            <MessageDisplay 
                error=error_message
                success=success_message
            />

            <main class="app-main">
                {move || match app_state.get() {
                    AppState::Locked => view! {
                        <LockScreen 
                            vault=vault
                            set_vault=set_vault
                            set_app_state=set_app_state
                            set_error=set_error_message
                        />
                    }.into_view(),
                    AppState::Unlocked { credentials } => view! {
                        <VaultDashboard
                            vault=vault
                            set_vault=set_vault
                            credentials=credentials
                            set_app_state=set_app_state
                            set_error=set_error_message
                            set_success=set_success_message
                        />
                    }.into_view(),
                }}
            </main>

            <footer class="app-footer">
                <p>"Built with Rust & Leptos | AES-256-GCM + Argon2id encryption"</p>
            </footer>
        </div>
    }
}


#[component]
fn MessageDisplay(
    error: ReadSignal<Option<String>>,
    success: ReadSignal<Option<String>>,
) -> impl IntoView {
    view! {
        <div class="message-container">
            {move || error.get().map(|msg| view! {
                <div class="message error-message">
                    <span class="message-icon">"X"</span>
                    <span class="message-text">{msg}</span>
                </div>
            })}
            
            {move || success.get().map(|msg| view! {
                <div class="message success-message">
                    <span class="message-icon">"✓ "</span>
                    <span class="message-text">{msg}</span>
                </div>
            })}
        </div>
    }
}

// WASM Entry Points
// This is called automatically when WASM loads
#[wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount_to_body(App);
}

//Tries if hydrate doesn't work
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    leptos::mount_to_body(App);
}