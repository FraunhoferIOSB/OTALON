<template>
  <div class="widget-root">
    <q-card flat bordered class="widget-card full-height">
      <q-card-section>
        <div class="row items-center no-wrap q-mb-sm">
          <q-icon name="shield" color="primary" size="20px" />
          <span class="text-subtitle1 text-weight-bold q-ml-sm">Security Advisories</span>
          <q-space />
        </div>
        <div class="text-center q-py-lg">
          <q-icon name="shield" size="48px" color="grey-5" />
          <div class="text-body2 text-muted q-mt-sm">Coming soon</div>
          <div class="text-caption text-muted q-mt-xs">
            Security advisories will be available after security advisories implementation.
          </div>
        </div>
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts"></script>

<style scoped lang="scss">
.widget-root {
  height: 100%;
}

.widget-card {
  display: flex;
  flex-direction: column;
  transition: box-shadow 0.2s ease;

  &:hover {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
  }
}
</style>
