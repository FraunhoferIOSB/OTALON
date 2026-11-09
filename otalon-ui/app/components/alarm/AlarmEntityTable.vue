<template>
  <q-card flat bordered>
    <q-card-section class="q-pb-none">
      <div class="row items-center no-wrap">
        <q-icon name="device_hub" color="primary" size="20px" />
        <span class="text-subtitle2 text-weight-bold q-ml-sm">Affected Entities</span>
        <q-space />
        <q-badge color="primary" :label="entities.length" />
      </div>
    </q-card-section>
    <q-card-section class="q-pt-sm q-pa-none">
      <q-table flat dense :rows="entities" :columns="columns" row-key="uci" :pagination="pagination" />
    </q-card-section>
  </q-card>
</template>

<script setup lang="ts">
import type { QTableColumn } from 'quasar'
import type { AlarmEntityDetail } from '~/types/golden-data'

/**
 * Display affected network entities for an alarm group.
 *
 * Shows MAC, IP, port, protocols, and UCI with client-side pagination.
 */

interface Props {
  entities: AlarmEntityDetail[]
}

defineProps<Props>()

const pagination = ref({
  page: 1,
  rowsPerPage: 5,
  sortBy: 'mac',
  descending: false,
})

const columns: QTableColumn[] = [
  { name: 'mac', label: 'MAC Address', field: 'mac', align: 'left', sortable: true },
  {
    name: 'ip',
    label: 'IP Address',
    field: 'ip',
    align: 'left',
    sortable: true,
    format: (val: string) => val || '—',
  },
  {
    name: 'port',
    label: 'Port',
    field: 'port',
    align: 'left',
    sortable: true,
    format: (val: number) => (val > 0 ? String(val) : '—'),
  },
  {
    name: 'protocols',
    label: 'Protocols',
    field: 'protocols',
    align: 'left',
    format: (val: string[]) => val.join(', '),
  },
  {
    name: 'uci',
    label: 'UCI',
    field: 'uci',
    align: 'left',
    style: 'max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;',
  },
]
</script>
