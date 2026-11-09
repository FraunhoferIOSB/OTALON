<template>
  <q-page class="operations-shell">
    <div class="operations-content">
      <NuxtPage />
    </div>
  </q-page>
</template>

<script setup lang="ts">
/**
 * Parent shell for the Operations route tree.
 *
 * Owns shared content edges, width, and top rhythm for `/operations/*`.
 */
</script>

<style scoped>
.operations-shell {
  width: 100%;
  min-width: 0;
}

.operations-content {
  box-sizing: border-box;
  width: 100%;
  min-width: 0;
  overflow-x: hidden;
  padding: 16px 16px 24px;
}

.operations-content :deep(> *) {
  box-sizing: border-box;
  width: 100%;
  min-width: 0;
  margin: 0;
}

@media (max-width: 700px) {
  .operations-content {
    padding-left: 76px;
  }
}
</style>
