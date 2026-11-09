import { useQuasar, type GlobalQuasarIconMapFn } from 'quasar'

const mapPlainIconsToSharp: GlobalQuasarIconMapFn = (iconName) => {
  if (iconName.includes(':') || iconName.includes(' ')) {
    return undefined
  }

  return {
    cls: 'material-icons-sharp',
    content: iconName,
  }
}

export default defineNuxtPlugin({
  name: 'quasar-icon-map',
  dependsOn: ['quasar'],
  setup() {
    const $q = useQuasar()
    $q.iconMapFn = mapPlainIconsToSharp
  },
})
