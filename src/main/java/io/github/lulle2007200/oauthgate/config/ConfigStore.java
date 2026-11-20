package io.github.lulle2007200.oauthgate.config;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

import com.google.gson.GsonBuilder;

public class ConfigStore {
	private static final IConfigCodec<?> configCodec = new GsonConfigCodec(
		new GsonBuilder()
			.disableHtmlEscaping()
			.setPrettyPrinting()
			.create()
	);

	private static <C, D, T> C loadImpl(Path configFile, IConfigMapper<C, D> mapper, IConfigCodec<T> configCodec)  throws IOException {
		ensureParentDir(configFile);

		D dto = null;

		if (Files.isRegularFile(configFile)) {
			T tree;
			try (Reader r = Files.newBufferedReader(configFile)) {
				tree = configCodec.readTree(r);
			}

			dto = mapper.getFormat().parse(tree, configCodec);
		} else {
			dto = mapper.getDefaultDto();
		}

		C config = mapper.fromDto(dto);
		try {
			save(configFile, config, mapper);
		} catch (ConfigException ex) {}

		return config;
	}

	public static <C, D> C load(Path configFile, IConfigMapper<C, D> mapper) {
		try {
			return loadImpl(configFile, mapper, configCodec);
		} catch (IOException ex) {
			throw new ConfigException("Failed to read config from file", ex);
		}
	}

	private static <C, D, T> void saveImpl(Path configFile, C config, IConfigMapper<C, D> mapper, IConfigCodec<T> configCodec) throws IOException {
		ensureParentDir(configFile);

		D dto = mapper.toDto(config);
		T tree = configCodec.dtoToTree(dto, mapper.getFormat().getCurrentVersion());

		Path tmp = configFile.resolveSibling(configFile.getFileName() + ".tmp");
		try (Writer w = Files.newBufferedWriter(tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
			configCodec.writeTree(tree, w);
		}
		Files.move(tmp, configFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
	}

	public static <C, D> void save(Path configFile, C config, IConfigMapper<C, D> mapper) {
		try {
			saveImpl(configFile, config, mapper, configCodec);
		} catch (IOException ex) {
			throw new ConfigException("Failed to save config to file", ex);
		}
	}

	private static void ensureParentDir(Path configFile) throws IOException {
		Path parent = configFile.getParent();
		if (parent != null && !Files.isDirectory(parent)) {
			Files.createDirectories(parent);
		}
	}
}