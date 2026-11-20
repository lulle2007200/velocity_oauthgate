package io.github.lulle2007200.oauthgate.config;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class VersionedFormat<D> {
	public static class Builder<D> {
		private final List<Class<?>> classes = new ArrayList<>();
		private final List<Function<Object, Object>> transformations = new ArrayList<>();

		public Builder(Class<D> cls) {
			classes.add(cls);
		}

		@SuppressWarnings("unchecked")
		public <N> Builder<N> next(Class<N> nextCls, Function<? super D, ? extends N> transformation) {
			transformations.add(o -> transformation.apply((D) o));
			classes.add(nextCls);
			return (Builder<N>) this;
		}

		public VersionedFormat<D> build() {
			return new VersionedFormat<D>(classes,
		                                  transformations);
		}
	}

	public static <T> Builder<T> newBuilder(Class<T> cls) {
		return new Builder<>(cls);
	}

	private final List<Class<?>> classes;
	private final List<Function<Object, Object>> transformations;

	protected VersionedFormat(List<Class<?>> classes,
                           List<Function<Object, Object>> transformations) {
		this.classes = classes;
		this.transformations = transformations;
	}

	public int getCurrentVersion() {
		return classes.size();
	}

	@SuppressWarnings("unchecked")
	public Class<D> getCurrentDto() {
		return (Class<D>) classes.getLast();
	}

	public Class<?> getDto(int version) {
		return classes.get(version - 1);
	}

	public <C> D parse(C content, IConfigCodec<C> reader) {
		int version = reader.getVersion(content);

		if (version < 1 || version > getCurrentVersion()) {
			throw new ConfigException("Unsupported config version");
		}

		Object dto = reader.treeToDto(content, getDto(version));

		for (; version < getCurrentVersion(); version++) {
			dto = transformations.get(version - 1).apply(dto);
		}

		try {
			return getCurrentDto().cast(dto);
		} catch (ClassCastException e) {
			throw new ConfigException("Config migration produced wrong type", e);
		}
	}

}