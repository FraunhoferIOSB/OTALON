<template>
  <div ref="widgetRoot" class="widget-root">
    <q-card flat bordered class="widget-card full-height">
      <q-card-section class="q-pb-none">
        <div class="row items-center no-wrap q-mb-sm">
          <q-icon name="bug_report" color="negative" size="20px" />
          <span class="text-subtitle1 text-weight-bold q-ml-sm">Vulnerabilities</span>
          <q-space />
          <q-btn flat dense size="sm" label="View All" color="primary" no-caps to="/devices" />
        </div>
      </q-card-section>
      <q-card-section class="q-pt-xs" style="overflow: auto; flex: 1 1 auto">
        <template v-if="dashboardStore.vulnerabilitySummary">
          <div class="row q-col-gutter-sm q-mb-sm">
            <div class="col-6">
              <div class="text-caption text-muted">Affected Devices</div>
              <div class="text-h6 text-weight-bold">
                {{ dashboardStore.vulnerabilitySummary.affected_device_count }}
              </div>
            </div>
            <div class="col-6">
              <div class="text-caption text-muted">Total CVEs</div>
              <div class="text-h6 text-weight-bold">
                {{ dashboardStore.vulnerabilitySummary.total_cve_count }}
              </div>
            </div>
          </div>
          <q-separator class="q-my-sm" />
          <div
            v-if="
              showSeverityBreakdown && Object.keys(dashboardStore.vulnerabilitySummary.severity_breakdown).length > 0
            "
            class="q-mb-sm"
          >
            <div class="text-caption text-muted q-mb-xs">Severity Breakdown</div>
            <div class="row q-gutter-x-sm">
              <q-badge
                v-for="(count, severity) in dashboardStore.vulnerabilitySummary.severity_breakdown"
                :key="severity"
                :color="severityColor(severity)"
                :label="`${severity}: ${count}`"
              />
            </div>
          </div>
          <q-separator v-if="showSeverityBreakdown" class="q-my-sm" />
          <div v-if="showTopCves && dashboardStore.vulnerabilitySummary.top_cves.length > 0">
            <div class="text-caption text-muted q-mb-xs">Top CVEs</div>
            <q-list dense>
              <q-item
                v-for="cve in dashboardStore.vulnerabilitySummary.top_cves"
                :key="cve.vuln_id"
                dense
                class="q-px-none"
              >
                <q-item-section>
                  <q-item-label class="text-body2 ellipsis">
                    {{ cve.vuln_id }}
                  </q-item-label>
                </q-item-section>
                <q-item-section side>
                  <q-badge :color="severityColor(cve.severity)" :label="cve.severity" />
                </q-item-section>
              </q-item>
            </q-list>
          </div>
        </template>
        <div v-else class="text-center text-grey q-pa-md">
          <q-icon name="bug_report" size="32px" class="q-mb-xs" />
          <div class="text-body2">No vulnerability data</div>
        </div>
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts">
import { useDashboardStore } from '~/stores/dashboardStore'
import { useWidgetSize } from '~/composables/useWidgetSize'

const dashboardStore = useDashboardStore()
const widgetRoot = ref<HTMLElement | null>(null)
const { height } = useWidgetSize(widgetRoot)

const showTopCves = computed(() => height.value >= 300)
const showSeverityBreakdown = computed(() => height.value >= 220)

function severityColor(severity: string): string {
  const s = String(severity).toLowerCase()
  if (s === 'critical') return 'negative'
  if (s === 'high') return 'warning'
  if (s === 'medium') return 'orange'
  if (s === 'low') return 'positive'
  return 'grey'
}
</script>

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
