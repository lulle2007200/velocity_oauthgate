package io.github.lulle2007200.oauthgate.config;

public interface IConfigMapper<C, D> {
	VersionedFormat<D> getFormat();
	D getDefaultDto();
	C fromDto(D dto);
	D toDto(C config);
}