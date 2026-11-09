<template>
  <div class="alarm-mac-asset-list">
    <div class="row items-center no-wrap q-mb-sm">
      <q-icon :name="DOMAIN_ICONS.assets" color="primary" size="20px" />
      <span class="text-subtitle2 text-weight-bold q-ml-sm">Affected Assets</span>
      <q-space />
      <q-badge color="primary" :label="macs.length" />
    </div>

    <q-list dense separator>
      <q-item
        v-for="asset in resolvedAssets"
        :key="asset.mac"
        v-ripple="!isNonUnicastMac(asset.mac)"
        dense
        :clickable="!isNonUnicastMac(asset.mac)"
        :class="['mac-link-item', { 'non-unicast-item': isNonUnicastMac(asset.mac) }]"
        @click="
          !isNonUnicastMac(asset.mac) && navigateTo(
            '/mac-timeseries?mac=' +
              encodeURIComponent(asset.mac) +
              (props.groupId ? '&alarmGroup=' + encodeURIComponent(props.groupId) : ''),
          )
        "
      >
        <q-tooltip v-if="isNonUnicastMac(asset.mac)">
          Gruppenadresse (Multicast/Broadcast) — kein einzelnes Gerät, keine Asset-Ansicht
        </q-tooltip>
        <q-item-section avatar>
          <q-icon :name="DOMAIN_ICONS.assets" size="16px" color="grey-7" />
        </q-item-section>
        <q-item-section>
          <q-item-label class="text-body2 text-weight-medium">
            {{ asset.display }}
          </q-item-label>
          <q-item-label caption class="text-mono">
            {{ asset.mac }}
          </q-item-label>
        </q-item-section>
        <q-item-section side>
          <q-badge v-if="isNonUnicastMac(asset.mac)" color="grey-6" label="multicast/broadcast" />
          <q-icon v-else name="open_in_new" size="14px" color="grey-6" />
        </q-item-section>
      </q-item>
    </q-list>

    <div v-if="macs.length === 0" class="text-center text-grey q-pa-xl">
      <q-icon name="link_off" size="48px" class="q-mb-sm" />
      <div class="text-subtitle1">No affected assets</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { computed, onMounted } from 'vue'
import { useDevicesStore } from '~/stores/devicesStore'
import { isNonUnicastMac, resolveAssetDisplay } from '~/utils/format'

interface AssetItem {
  mac: string
  display: string
}

interface Props {
  macs: string[]
  groupId?: string
}

const props = withDefaults(defineProps<Props>(), {
  groupId: '',
})

const devicesStore = useDevicesStore()

onMounted(() => {
  if (devicesStore.devices.length === 0) {
    void devicesStore.fetchDevices()
  }
})

const resolvedAssets = computed<AssetItem[]>(() => {
  const devices = devicesStore.devices
  return props.macs.map((mac) => ({
    mac,
    display: resolveAssetDisplay(mac, devices),
  }))
})
</script>

<style scoped lang="scss">
.mac-link-item {
  border-radius: 4px;
  transition: background-color 0.15s ease;

  &:hover {
    background-color: rgba(var(--cd-primary-rgb), 0.08);
  }
}

/* Multicast/broadcast group addresses are not devices: no navigation target
   exists, so they must not look interactive (UI-092). */
.non-unicast-item {
  cursor: default;
  opacity: 0.72;

  &:hover {
    background-color: transparent;
  }
}

.text-mono {
  font-family: $font-family-mono;
}
</style>
