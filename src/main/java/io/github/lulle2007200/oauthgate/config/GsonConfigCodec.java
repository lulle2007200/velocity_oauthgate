package io.github.lulle2007200.oauthgate.config;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

public class GsonConfigCodec implements IConfigCodec<JsonObject> {
	private static final String versionKey = "version";
	private final Gson gson;

	public GsonConfigCodec(Gson gson) {
		this.gson = gson;
	}

	@Override
	public int getVersion(JsonObject content) {
		JsonElement versionEl = content.get(versionKey);
		if (versionEl == null) {
			return 1;
		}
		try {
			return versionEl.getAsInt();
		} catch (RuntimeException e) {
			throw new ConfigException("Invalid version field", e);
		}
	}

	@Override
	public <T> T treeToDto(JsonObject content, Class<T> cls) {
		try {
			T res = gson.fromJson(content, cls);
			if (res == null) {
				throw new ConfigException("Config content is empty");
			}
			return res;
		} catch (JsonParseException e) {
			throw new ConfigException("Invalid config content", e);
		}
	}

	@Override
	public JsonObject dtoToTree(Object dto, int version) {
	    try {
	    	JsonObject json = gson.toJsonTree(dto).getAsJsonObject();
	    	json.addProperty(versionKey, version);
	    	return json;
	    } catch (JsonParseException | IllegalStateException e) {
	    	throw new ConfigException("Cannot serialize config", e);
	    }
	}

	@Override
	public JsonObject readTree(Reader in) {
		try {
			JsonElement json = JsonParser.parseReader(in);
			if (!json.isJsonObject()) {
				throw new ConfigException("Config is invalid");
			}
			return json.getAsJsonObject();
		} catch (JsonParseException e) {
			throw new ConfigException("Config is invalid", e);
		}
	}

	@Override
	public void writeTree(JsonObject tree, Writer out) {
		try {
			gson.toJson(tree, out);
		} catch (JsonIOException e) {
			throw new ConfigException("Failed to write config", e);
		}
	}
}