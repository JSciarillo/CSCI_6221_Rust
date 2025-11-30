//User interface components
use leptos::*;
use crate::vault::{Vault, Credential};
use crate::crypto::SecureString;
use crate::password_generator::{PasswordGenerator, PasswordOptions, PasswordStrength};
use crate::AppState;

//Lock screen
#[component]
pub fn LockScreen(
    vault: ReadSignal<Option<Vault>>,
    set_vault: WriteSignal<Option<Vault>>,
    set_app_state: WriteSignal<AppState>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (master_password, set_master_password) = create_signal(String::new());
    let (confirm_password, set_confirm_password) = create_signal(String::new());
    let (is_initializing, set_is_initializing) = create_signal(false);
    let (loading, set_loading) = create_signal(false);

    let vault_exists = move || {
        vault.get().map(|v| v.exists()).unwrap_or(false)
    };

    let handle_unlock = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_loading.set(true);
        set_error.set(None);

        if let Some(mut v) = vault.get() {
            match v.unlock(&master_password.get()) {
                Ok(_) => {
                    match v.list_credentials() {
                        Ok(creds) => {
                            set_vault.set(Some(v.clone()));
                            set_app_state.set(AppState::Unlocked { credentials: creds });
                            set_master_password.set(String::new());
                        }
                        Err(e) => set_error.set(Some(format!("Failed to load credentials: {}", e))),
                    }
                }
                Err(_) => set_error.set(Some("Invalid master password".to_string())),
            }
        }
        set_loading.set(false);
    };

    let handle_initialize = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_loading.set(true);
        set_error.set(None);

        let pw = master_password.get();
        let confirm = confirm_password.get();

        if pw.len() < 8 {
            set_error.set(Some("Password must be at least 8 characters".to_string()));
            set_loading.set(false);
            return;
        }

        if pw != confirm {
            set_error.set(Some("Passwords don't match".to_string()));
            set_loading.set(false);
            return;
        }

        if let Some(mut v) = vault.get() {
            match v.initialize(&pw) {
                Ok(_) => {
                    set_vault.set(Some(v.clone()));
                    set_app_state.set(AppState::Unlocked { credentials: vec![] });
                    set_master_password.set(String::new());
                    set_confirm_password.set(String::new());
                }
                Err(e) => set_error.set(Some(format!("Initialization failed: {}", e))),
            }
        }
        set_loading.set(false);
    };

    view! {
        <div class="lock-screen">
            <div class="lock-screen-card">
                <div class="lock-icon">
                    <img src="/new-lock-img.png" alt="Lock" />
                </div>
                
                {move || if vault_exists() {
                    view! {
                        <div>
                            <h2>"Unlock Vault"</h2>
                            <p class="hint">"Enter your master password"</p>
                            
                            <form on:submit=handle_unlock>
                                <div class="form-group">
                                    <input 
                                        type="password"
                                        placeholder="Master Password"
                                        class="input-field"
                                        prop:value=move || master_password.get()
                                        on:input=move |ev| set_master_password.set(event_target_value(&ev))
                                        disabled=move || loading.get()
                                    />
                                </div>
                                
                                <button 
                                    type="submit" 
                                    class="btn btn-primary"
                                    disabled=move || loading.get() || master_password.get().is_empty()
                                >
                                    {move || if loading.get() { "Unlocking..." } else { "Unlock" }}
                                </button>
                            </form>
                        </div>
                    }.into_view()
                } else {
                    view! {
                        <div>
                            <h2>"Initialize New Vault"</h2>
                            <p class="hint">"Create a strong master password (≥8 characters)"</p>
                            
                            {move || if !is_initializing.get() {
                                view! {
                                    <button 
                                        class="btn btn-primary"
                                        on:click=move |_| set_is_initializing.set(true)
                                    >
                                        "Create New Vault"
                                    </button>
                                }.into_view()
                            } else {
                                view! {
                                    <form on:submit=handle_initialize>
                                        <div class="form-group">
                                            <input 
                                                type="password"
                                                placeholder="Master Password"
                                                class="input-field"
                                                prop:value=move || master_password.get()
                                                on:input=move |ev| set_master_password.set(event_target_value(&ev))
                                                disabled=move || loading.get()
                                            />
                                        </div>
                                        
                                        <div class="form-group">
                                            <input 
                                                type="password"
                                                placeholder="Confirm Password"
                                                class="input-field"
                                                prop:value=move || confirm_password.get()
                                                on:input=move |ev| set_confirm_password.set(event_target_value(&ev))
                                                disabled=move || loading.get()
                                            />
                                        </div>
                                        
                                        <div class="button-group">
                                            <button 
                                                type="button"
                                                class="btn btn-secondary"
                                                on:click=move |_| {
                                                    set_is_initializing.set(false);
                                                    set_master_password.set(String::new());
                                                    set_confirm_password.set(String::new());
                                                }
                                                disabled=move || loading.get()
                                            >
                                                "Cancel"
                                            </button>
                                            
                                            <button 
                                                type="submit" 
                                                class="btn btn-primary"
                                                disabled=move || loading.get() || master_password.get().is_empty()
                                            >
                                                {move || if loading.get() { "Creating..." } else { "Create Vault" }}
                                            </button>
                                        </div>
                                    </form>
                                }.into_view()
                            }}
                        </div>
                    }.into_view()
                }}
            </div>
        </div>
    }
}


//Vault dashboard
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ViewMode {
    List,
    Add,
    Generate,
}

#[component]
pub fn VaultDashboard(
    vault: ReadSignal<Option<Vault>>,
    set_vault: WriteSignal<Option<Vault>>,
    credentials: Vec<Credential>,
    set_app_state: WriteSignal<AppState>,
    set_error: WriteSignal<Option<String>>,
    set_success: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (view_mode, set_view_mode) = create_signal(ViewMode::List);
    let (credentials_signal, set_credentials) = create_signal(credentials);
    let (search_query, set_search_query) = create_signal(String::new());

    let handle_lock = move |_| {
        if let Some(mut v) = vault.get() {
            v.lock();
        }
        set_app_state.set(AppState::Locked);
    };

    let handle_delete_vault = move |_| {
    if let Some(window) = web_sys::window() {
        if window.confirm_with_message("DELETE ENTIRE VAULT?\n\nThis will permanently delete:\n• All credentials\n• Master password\n• All vault data\n\nThis CANNOT be undone!\n\nAre you absolutely sure?").unwrap_or(false) {
            //clear local storage
            if let Ok(Some(storage)) = window.local_storage() {
                let _ = storage.clear();
            }
            
            //Create a new empty vault
            match Vault::new() {
                Ok(new_vault) => {
                    set_vault.set(Some(new_vault));
                    set_app_state.set(AppState::Locked);
                    set_success.set(Some("Vault deleted successfully. Create a new vault to continue.".to_string()));
                }
                Err(e) => {
                    set_error.set(Some(format!("Failed to create new vault: {}", e)));
                }
            }
        }
    }
};

    let refresh_credentials = move || {
        if let Some(mut v) = vault.get() {
            match v.list_credentials() {
                Ok(creds) => {
                    set_vault.set(Some(v.clone()));
                    set_credentials.set(creds);
                }
                Err(e) => set_error.set(Some(format!("Failed to refresh: {}", e))),
            }
        }
    };

    let filtered_credentials = move || {
        let query = search_query.get().to_lowercase();
        if query.is_empty() {
            credentials_signal.get()
        } else {
            credentials_signal.get()
                .into_iter()
                .filter(|c| {
                    c.service.to_lowercase().contains(&query) ||
                    c.username.to_lowercase().contains(&query)
                })
                .collect()
        }
    };

    view! {
        <div class="dashboard">
            <div class="dashboard-header">
                <div class="search-bar">
                    <input 
                        type="text"
                        placeholder="Search Credentials"
                        class="search-input"
                        prop:value=move || search_query.get()
                        on:input=move |ev| set_search_query.set(event_target_value(&ev))
                    />
                </div>
                
                <div class="header-actions">
                    <button 
                        class="btn btn-secondary"
                        on:click=move |_| set_view_mode.set(ViewMode::Add)
                    >
                        "Add"
                    </button>
                    
                    <button 
                        class="btn btn-secondary"
                        on:click=move |_| set_view_mode.set(ViewMode::Generate)
                    >
                        "Generate"
                    </button>
                    
                    <button 
                        class="btn btn-danger"
                        on:click=handle_lock
                    >
                        <img src="/new-lock-img.png" alt="Lock" style="width: 16px; height: 16px; margin-right: 4px; vertical-align: middle;" />
                        "Lock"
                    </button>
                    
                    <button 
                        class="btn btn-danger"
                        on:click=handle_delete_vault
                        style="background-color: #c41e3a;"
                        title="Permanently delete entire vault"
                    >
                        "Delete Vault"
                    </button>
                </div>
            </div>

            <div class="dashboard-content">
                {move || match view_mode.get() {
                    ViewMode::List => view! {
                        <CredentialList 
                            credentials=filtered_credentials()
                            vault=vault
                            set_vault=set_vault
                            set_error=set_error
                            set_success=set_success
                            refresh=refresh_credentials
                        />
                    }.into_view(),
                    ViewMode::Add => view! {
                        <AddCredentialForm
                            vault=vault
                            set_vault=set_vault
                            set_view_mode=set_view_mode
                            set_error=set_error
                            set_success=set_success
                            refresh=refresh_credentials
                        />
                    }.into_view(),
                    ViewMode::Generate => view! {
                        <PasswordGeneratorView
                            set_view_mode=set_view_mode
                        />
                    }.into_view(),
                }}
            </div>

            <div class="dashboard-footer">
                <span>"Total: " {move || credentials_signal.get().len()}</span>
                <span>"Showing: " {move || filtered_credentials().len()}</span>
            </div>
        </div>
    }
}


//Credential list
#[component]
pub fn CredentialList<F>(
    credentials: Vec<Credential>,
    vault: ReadSignal<Option<Vault>>,
    set_vault: WriteSignal<Option<Vault>>,
    set_error: WriteSignal<Option<String>>,
    set_success: WriteSignal<Option<String>>,
    refresh: F,
) -> impl IntoView 
where
    F: Fn() + 'static + Clone
{
    if credentials.is_empty() {
        return view! {
            <div class="empty-state">
                <div class="empty-icon"></div>
                <h3>"No Credentials Yet"</h3>
                <p>"Add your first credential to get started"</p>
            </div>
        }.into_view();
    }

    view! {
        <div class="credential-list">
            <For
                each=move || credentials.clone()
                key=|cred| cred.id.clone()
                children=move |cred| {
                    view! {
                        <CredentialCard
                            credential=cred
                            vault=vault
                            set_vault=set_vault
                            set_error=set_error
                            set_success=set_success
                            refresh=refresh.clone()
                        />
                    }
                }
            />
        </div>
    }.into_view()
}


//Credential card
#[component]
pub fn CredentialCard<F>(
    credential: Credential,
    vault: ReadSignal<Option<Vault>>,
    set_vault: WriteSignal<Option<Vault>>,
    set_error: WriteSignal<Option<String>>,
    set_success: WriteSignal<Option<String>>,
    refresh: F,
) -> impl IntoView
where
    F: Fn() + 'static
{
    let (show_password, set_show_password) = create_signal(false);
    let (password, set_password) = create_signal(String::new());
    let (expanded, set_expanded) = create_signal(false);

    let service = credential.service.clone();
    let username = credential.username.clone();
    let notes = credential.notes.clone();
    let created = credential.created_at.format("%Y-%m-%d %H:%M").to_string();

    let service_show = service.clone();
    let service_copy = service.clone();
    let service_delete = service.clone();

    let handle_show_password = move |_| {
        if show_password.get() {
            set_show_password.set(false);
            set_password.set(String::new());
        } else {
            if let Some(mut v) = vault.get() {
                match v.get_credential(&service_show) {
                    Ok(cred) => {
                        if let Some(pw) = cred.password {
                            set_vault.set(Some(v.clone()));
                            set_password.set(pw.as_str().to_string());
                            set_show_password.set(true);
                        }
                    }
                    Err(e) => set_error.set(Some(format!("Failed to get password: {}", e))),
                }
            }
        }
    };

    let handle_copy = move |_| {
        let Some(mut v) = vault.get() else { return };
        
        let cred = match v.get_credential(&service_copy) {
            Ok(cred) => cred,
            Err(e) => {
                set_error.set(Some(format!("Failed to copy: {}", e)));
                return;
            }
        };
        
        set_vault.set(Some(v.clone()));
        
        let Some(pw) = cred.password else { return };
        let Some(window) = web_sys::window() else { return };
        
        let clipboard = window.navigator().clipboard();
        let _ = clipboard.write_text(pw.as_str());
        set_success.set(Some(format!("Password copied for {}", service_copy)));
    };

    let handle_delete = move |_| {
        if let Some(mut v) = vault.get() {
            match v.remove_credential(&service_delete) {
                Ok(_) => {
                    set_vault.set(Some(v.clone()));
                    set_success.set(Some(format!("Deleted {}", service_delete)));
                    refresh();
                }
                Err(e) => set_error.set(Some(format!("Failed to delete: {}", e))),
            }
        }
    };

    view! {
        <div class="credential-card">
            <div class="card-header">
                <div class="card-title">
                    <span class="service-icon">
                        <img src="/key-img.png" alt="Key" />
                    </span>
                    <h3>{service.clone()}</h3>
                </div>
                
                <button 
                    class="btn-icon"
                    on:click=move |_| set_expanded.set(!expanded.get())
                >
                    {move || if expanded.get() { "v" } else { ">" }}
                </button>
            </div>

            <div class="card-body">
                <div class="credential-info">
                    <div class="info-row">
                        <span class="info-label">"Username:"</span>
                        <span class="info-value">{username}</span>
                    </div>

                    {move || if expanded.get() {
                        view! {
                            <div>
                                <div class="info-row">
                                    <span class="info-label">"Created:"</span>
                                    <span class="info-value">{created.clone()}</span>
                                </div>
                                
                                {notes.clone().map(|n| view! {
                                    <div class="info-row">
                                        <span class="info-label">"Notes:"</span>
                                        <span class="info-value">{n}</span>
                                    </div>
                                })}

                                {move || if show_password.get() {
                                    view! {
                                        <div class="info-row password-row">
                                            <span class="info-label">"Password:"</span>
                                            <code class="password-display">{password.get()}</code>
                                        </div>
                                    }.into_view()
                                } else {
                                    view! { <div></div> }.into_view()
                                }}
                            </div>
                        }.into_view()
                    } else {
                        view! { <div></div> }.into_view()
                    }}
                </div>

                <div class="card-actions">
                    <button 
                        class="btn btn-small"
                        on:click=handle_show_password
                    >
                        {move || if show_password.get() { "Hide" } else { "Show" }}
                    </button>
                    
                    <button 
                        class="btn btn-small"
                        on:click=handle_copy
                    >
                        "Copy"
                    </button>
                    
                    <button 
                        class="btn btn-small btn-danger"
                        on:click=handle_delete
                    >
                        "Delete"
                    </button>
                </div>
            </div>
        </div>
    }
}


//Adding new credentials form
#[component]
pub fn AddCredentialForm<F>(
    vault: ReadSignal<Option<Vault>>,
    set_vault: WriteSignal<Option<Vault>>,
    set_view_mode: WriteSignal<ViewMode>,
    set_error: WriteSignal<Option<String>>,
    set_success: WriteSignal<Option<String>>,
    refresh: F,
) -> impl IntoView
where
    F: Fn() + 'static
{
    let (service, set_service) = create_signal(String::new());
    let (username, set_username) = create_signal(String::new());
    let (password, set_password) = create_signal(String::new());
    let (notes, set_notes) = create_signal(String::new());
    let (loading, set_loading) = create_signal(false);

    let handle_generate = move |_| {
        match PasswordGenerator::generate(&PasswordOptions::default()) {
            Ok(pw) => set_password.set(pw),
            Err(e) => set_error.set(Some(format!("Generation failed: {}", e))),
        }
    };

    let handle_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_loading.set(true);

        let svc = service.get();
        let user = username.get();
        let pw = password.get();
        let note = notes.get();

        if svc.is_empty() || user.is_empty() || pw.is_empty() {
            set_error.set(Some("Service, username, and password are required".to_string()));
            set_loading.set(false);
            return;
        }

        if let Some(mut v) = vault.get() {
            let note_opt = if note.is_empty() { None } else { Some(note) };
            
            match v.add_credential(
                svc.clone(),
                user,
                SecureString::new(pw),
                note_opt,
            ) {
                Ok(_) => {
                    set_vault.set(Some(v.clone()));
                    set_success.set(Some(format!("Added {}", svc)));
                    refresh();
                    set_view_mode.set(ViewMode::List);
                }
                Err(e) => set_error.set(Some(format!("Failed to add: {}", e))),
            }
        }

        set_loading.set(false);
    };

    let password_strength = move || {
        let pw = password.get();
        if pw.is_empty() {
            return None;
        }
        Some(PasswordGenerator::assess_strength(&pw))
    };

    view! {
        <div class="form-container">
            <div class="form-header">
                <h2>"Add New Credential"</h2>
                <button 
                    class="btn-icon"
                    on:click=move |_| set_view_mode.set(ViewMode::List)
                >
                    "X"
                </button>
            </div>

            <form on:submit=handle_submit>
                <div class="form-group">
                    <label>"Service Name"</label>
                    <input 
                        type="text"
                        placeholder="e.g., Gmail, GitHub, Netflix"
                        class="input-field"
                        prop:value=move || service.get()
                        on:input=move |ev| set_service.set(event_target_value(&ev))
                        disabled=move || loading.get()
                    />
                </div>

                <div class="form-group">
                    <label>"Username / Email"</label>
                    <input 
                        type="text"
                        placeholder="your@email.com"
                        class="input-field"
                        prop:value=move || username.get()
                        on:input=move |ev| set_username.set(event_target_value(&ev))
                        disabled=move || loading.get()
                    />
                </div>

                <div class="form-group">
                    <label>"Password"</label>
                    <div class="password-input-group">
                        <input 
                            type="text"
                            placeholder="Enter or generate password"
                            class="input-field"
                            prop:value=move || password.get()
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                            disabled=move || loading.get()
                        />
                        <button 
                            type="button"
                            class="btn btn-secondary"
                            on:click=handle_generate
                            disabled=move || loading.get()
                        >
                            "Generate"
                        </button>
                    </div>
                    
                    {move || password_strength().map(|strength| {
                        let (color, text) = match strength {
                            PasswordStrength::VeryWeak => ("strength-very-weak", "Very Weak"),
                            PasswordStrength::Weak => ("strength-weak", "Weak"),
                            PasswordStrength::Fair => ("strength-fair", "Fair"),
                            PasswordStrength::Strong => ("strength-strong", "Strong"),
                            PasswordStrength::VeryStrong => ("strength-very-strong", "Very Strong"),
                        };
                        
                        view! {
                            <div class={format!("strength-indicator {}", color)}>
                                "Strength: " {text}
                            </div>
                        }
                    })}
                </div>

                <div class="form-group">
                    <label>"Notes (Optional)"</label>
                    <textarea 
                        placeholder="Additional information..."
                        class="input-field textarea"
                        prop:value=move || notes.get()
                        on:input=move |ev| set_notes.set(event_target_value(&ev))
                        disabled=move || loading.get()
                    />
                </div>

                <div class="button-group">
                    <button 
                        type="button"
                        class="btn btn-secondary"
                        on:click=move |_| set_view_mode.set(ViewMode::List)
                        disabled=move || loading.get()
                    >
                        "Cancel"
                    </button>
                    
                    <button 
                        type="submit"
                        class="btn btn-primary"
                        disabled=move || loading.get()
                    >
                        {move || if loading.get() { "Adding..." } else { "Add" }}
                    </button>
                </div>
            </form>
        </div>
    }
}

//Password generator view
#[component]
pub fn PasswordGeneratorView(
    set_view_mode: WriteSignal<ViewMode>,
) -> impl IntoView {
    let (length, set_length) = create_signal(16);
    let (include_uppercase, set_include_uppercase) = create_signal(true);
    let (include_numbers, set_include_numbers) = create_signal(true);
    let (include_special, set_include_special) = create_signal(true);
    let (generated_passwords, set_generated_passwords) = create_signal::<Vec<(String, PasswordStrength)>>(vec![]);

    let generate_passwords = move |_| {
        let mut opts = PasswordOptions::default();
        opts.length = length.get();
        opts.include_uppercase = include_uppercase.get();
        opts.include_numbers = include_numbers.get();
        opts.include_special = include_special.get();

        let mut passwords = Vec::new();
        for _ in 0..5 {
            if let Ok(pw) = PasswordGenerator::generate(&opts) {
                let strength = PasswordGenerator::assess_strength(&pw);
                passwords.push((pw, strength));
            }
        }
        set_generated_passwords.set(passwords);
    };

    view! {
        <div class="form-container">
            <div class="form-header">
                <h2>"Password Generator"</h2>
                <button 
                    class="btn-icon"
                    on:click=move |_| set_view_mode.set(ViewMode::List)
                >
                    "X"
                </button>
            </div>

            <div class="generator-options">
                <div class="form-group">
                    <label>"Length: " {move || length.get()}</label>
                    <input 
                        type="range"
                        min="8"
                        max="64"
                        class="slider"
                        prop:value=move || length.get()
                        on:input=move |ev| {
                            if let Ok(val) = event_target_value(&ev).parse::<usize>() {
                                set_length.set(val);
                            }
                        }
                    />
                </div>

                <div class="checkbox-group">
                    <label class="checkbox-label">
                        <input 
                            type="checkbox"
                            prop:checked=move || include_uppercase.get()
                            on:change=move |ev| set_include_uppercase.set(event_target_checked(&ev))
                        />
                        " Include Uppercase (A-Z)"
                    </label>

                    <label class="checkbox-label">
                        <input 
                            type="checkbox"
                            prop:checked=move || include_numbers.get()
                            on:change=move |ev| set_include_numbers.set(event_target_checked(&ev))
                        />
                        " Include Numbers (0-9)"
                    </label>

                    <label class="checkbox-label">
                        <input 
                            type="checkbox"
                            prop:checked=move || include_special.get()
                            on:change=move |ev| set_include_special.set(event_target_checked(&ev))
                        />
                        " Include Special (!@#$%...)"
                    </label>
                </div>

                <button 
                    class="btn btn-primary"
                    on:click=generate_passwords
                >
                    "Generate Passwords"
                </button>
            </div>

            <div class="generated-passwords">
                <For
                    each=move || generated_passwords.get()
                    key=|(pw, _)| pw.clone()
                    children=|(pw, strength)| {
                        let (color, text) = match strength {
                            PasswordStrength::VeryWeak => ("strength-very-weak", "Very Weak"),
                            PasswordStrength::Weak => ("strength-weak", "Weak"),
                            PasswordStrength::Fair => ("strength-fair", "Fair"),
                            PasswordStrength::Strong => ("strength-strong", "Strong"),
                            PasswordStrength::VeryStrong => ("strength-very-strong", "Very Strong"),
                        };

                        view! {
                            <div class="generated-password-item">
                                <code class="password-code">{pw.clone()}</code>
                                <span class={format!("strength-badge {}", color)}>{text}</span>
                            </div>
                        }
                    }
                />
            </div>
        </div>
    }
}