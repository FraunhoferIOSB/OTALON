<template>
  <div class="alarm-protocol-list">
    <div class="row items-center no-wrap q-mb-sm">
      <q-icon :name="DOMAIN_ICONS.protocols" color="primary" size="20px" />
      <span class="text-subtitle2 text-weight-bold q-ml-sm">Affected Protocols</span>
      <q-space />
      <q-badge color="primary" :label="protos.length" />
    </div>

    <q-list dense separator>
      <q-item
        v-for="proto in protos"
        :key="proto.id"
        v-ripple
        dense
        clickable
        class="protocol-link-item"
        @click="
          navigateTo(
            '/proto-timeseries?proto=' +
              encodeURIComponent(proto.label) +
              '&alarmProtoId=' +
              encodeURIComponent(proto.id) +
              (groupId ? '&alarmGroup=' + encodeURIComponent(groupId) : ''),
          )
        "
      >
        <q-item-section avatar>
          <q-icon name="swap_horiz" size="16px" color="grey-7" />
        </q-item-section>
        <q-item-section>
          <q-item-label class="text-body2 text-weight-medium text-mono">
            {{ proto.label }}
          </q-item-label>
          <q-item-label caption>
            {{ topProtocol(proto.label) }}
          </q-item-label>
        </q-item-section>
        <q-item-section side>
          <q-icon name="open_in_new" size="14px" color="grey-6" />
        </q-item-section>
      </q-item>
    </q-list>

    <div v-if="protos.length === 0" class="text-center text-grey q-pa-xl">
      <q-icon name="link_off" size="48px" class="q-mb-sm" />
      <div class="text-subtitle1">No affected protocols</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { DOMAIN_ICONS } from '~/composables/useNavigation'
/**
 * Display protocol stacks as a scrollable list.
 *
 * Each entry shows the human-readable protocol label and navigates
 * to the protocol timeseries subpage pre-filtered by the series id
 * and optional alarm group.
 */
import { humanizeProtocolStack } from '~/utils/protocol'

export interface ProtocolListItem {
  id: string
  label: string
}

interface Props {
  protos: ProtocolListItem[]
  groupId?: string
}

withDefaults(defineProps<Props>(), {
  groupId: '',
})

/**
 * Extract the top (most specific) protocol from a stack label.
 *
 * Returns the last colon-separated segment with underscores replaced
 * by spaces, e.g.
 * ``Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO`` → ``PROFINET RT IO``.
 */
function topProtocol(label: string): string {
  return humanizeProtocolStack(label)
}
</script>

<style scoped lang="scss">
.protocol-link-item {
  border-radius: 4px;
  transition: background-color 0.15s ease;

  &:hover {
    background-color: rgba(var(--cd-primary-rgb), 0.08);
  }
}

.text-mono {
  font-family: $font-family-mono;
}
</style>
