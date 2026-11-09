<template>
  <q-page class="row items-center justify-center">
    <q-spinner-dots size="40px" color="primary" />
  </q-page>
</template>

<script setup lang="ts">
definePageMeta({
  title: 'OTALON',
})

await navigateTo('/dashboard', { replace: true })
</script>
