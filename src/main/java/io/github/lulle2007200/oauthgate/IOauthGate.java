package io.github.lulle2007200.oauthgate;

import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PreTransferEvent;

public interface IOauthGate {
	void onLogin(LoginEvent event);
	void onPreTransfer(PreTransferEvent event);
	void onLogout(DisconnectEvent event);
}