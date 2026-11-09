<template>
  <div class="alarm-connection-list">
    <div class="row items-center no-wrap q-mb-sm">
      <q-icon :name="DOMAIN_ICONS.connections" color="primary" size="20px" />
      <span class="text-subtitle2 text-weight-bold q-ml-sm">Affected Connections</span>
      <q-space />
      <q-badge color="primary" :label="collapsedSeriesIds.length" />
    </div>

    <q-list dense separator>
      <q-item
        v-for="(conn, idx) in parsedConnections"
        :key="idx"
        v-ripple
        dense
        clickable
        class="connection-link-item"
        @click="
          navigateTo(
            '/connections?uci=' +
              encodeURIComponent(collapsedSeriesIds[idx] ?? '') +
              (props.groupId ? '&alarmGroup=' + encodeURIComponent(props.groupId) : ''),
          )
        "
      >
        <q-item-section avatar>
          <q-icon name="swap_horiz" size="16px" color="grey-7" />
        </q-item-section>
        <q-item-section>
          <q-item-label class="text-body2 text-mono">
            {{ conn.summary }}
          </q-item-label>
          <q-item-label caption>
            {{ conn.protocol }}
          </q-item-label>
        </q-item-section>
        <q-item-section side>
          <q-icon name="open_in_new" size="14px" color="grey-6" />
        </q-item-section>
      </q-item>
    </q-list>

    <div v-if="collapsedSeriesIds.length === 0" class="text-center text-grey q-pa-xl">
      <q-icon name="link_off" size="48px" class="q-mb-sm" />
      <div class="text-subtitle1">No affected connections</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { collapsePortUcis } from '~/utils/uci'

/**
 * Display series_ids as a scrollable list of affected connections.
 *
 * Each series_id has the format:
 * src_mac/dst_mac/vlan/l3_proto/src_ip/dst_ip/src_port/dst_port/proto_stack
 *
 * This component parses the series_id and shows a shortened view:
 * src_mac → dst_mac with the last protocol from the stack.
 */

interface ParsedConnection {
  summary: string
  protocol: string
}

interface Props {
  seriesIds: string[]
  groupId?: string
}

const props = withDefaults(defineProps<Props>(), {
  groupId: '',
})

const collapsedSeriesIds = computed<string[]>(() => collapsePortUcis(props.seriesIds))

/**
 * Parse a series_id string into a display-friendly connection object.
 *
 * @param seriesId - Raw connection identifier string.
 * @returns Parsed connection with summary and protocol.
 */
function parseSeriesId(seriesId: string): ParsedConnection {
  const parts = seriesId.split('/')
  const srcMac = parts[0] ?? '?'
  const dstMac = parts[1] ?? '?'
  const protoStack = parts[parts.length - 1] ?? ''
  const protocols = protoStack.split(':')
  const lastProto = protocols[protocols.length - 1] ?? protoStack

  const srcIp = parts[4] ?? ''
  const dstIp = parts[5] ?? ''
  const ipInfo = srcIp && dstIp ? ` (${srcIp} → ${dstIp})` : ''

  return {
    summary: `${srcMac} → ${dstMac}${ipInfo}`,
    protocol: lastProto || 'Unknown',
  }
}

const parsedConnections = computed<ParsedConnection[]>(() => collapsedSeriesIds.value.map(parseSeriesId))
</script>

<style scoped lang="scss">
.connection-link-item {
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
