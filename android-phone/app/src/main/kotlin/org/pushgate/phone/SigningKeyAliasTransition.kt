package org.pushgate.phone

internal class SigningKeyAliasTransition(
    private val defaultAlias: String,
    private val readActiveAlias: () -> String?,
    private val writeActiveAlias: (String?) -> Boolean,
    private val clearAlias: (String) -> Unit
) {
    fun activeAlias(): String = readActiveAlias()?.takeIf { it.isNotBlank() } ?: defaultAlias

    fun select(stagedAlias: String): String {
        require(stagedAlias.isNotBlank()) { "Staged signing key alias is blank" }
        val previousAlias = activeAlias()
        check(writeActiveAlias(stagedAlias)) { "Could not persist active signing key alias" }
        return previousAlias
    }

    fun finishSelection(previousAlias: String) {
        if (previousAlias != activeAlias()) clearAlias(previousAlias)
    }

    fun activate(stagedAlias: String) {
        finishSelection(select(stagedAlias))
    }

    fun discard(stagedAlias: String) {
        if (stagedAlias != activeAlias()) clearAlias(stagedAlias)
    }

    fun clearActive() {
        clearAll(emptySet())
    }

    fun clearAll(additionalAliases: Set<String>) {
        val aliases = buildSet {
            add(activeAlias())
            add(defaultAlias)
            addAll(additionalAliases.filter(String::isNotBlank))
        }
        check(writeActiveAlias(null)) { "Could not clear active signing key alias" }
        aliases.forEach(clearAlias)
    }
}
