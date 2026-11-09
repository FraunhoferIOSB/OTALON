<template>
  <div class="row items-center justify-center q-pa-lg">
    <q-spinner-dots size="32px" color="primary" />
  </div>
</template>

<script setup lang="ts">
/**
 * Operations index — redirects to the Overview subpage.
 */
await navigateTo('/operations/overview', { replace: true })
</script>
