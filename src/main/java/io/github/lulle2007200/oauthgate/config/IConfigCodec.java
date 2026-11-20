package io.github.lulle2007200.oauthgate.config;

import java.io.Reader;
import java.io.Writer;

public interface IConfigCodec<C> {
	int getVersion(C content);
	C readTree(Reader in);
	void writeTree(C tree, Writer out);
	<T> T treeToDto(C tree, Class<T> cls);
	C dtoToTree(Object dto, int version);
}