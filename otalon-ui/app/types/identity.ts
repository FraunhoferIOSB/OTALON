/** Product identity contracts returned by otalon-api. */

export type ProductUserRole = 'admin' | 'operator' | 'viewer'

export interface CurrentUser {
  id: number
  username: string
  role: ProductUserRole
  must_change_password: boolean
}

export interface LoginResponse {
  username: string
  role: ProductUserRole
  must_change_password: boolean
}

export interface AdminUser {
  id: number
  username: string
  role: ProductUserRole
  disabled: boolean
  must_change_password: boolean
  created_at: string | null
  last_login_at: string | null
}

export interface UserListResponse {
  users: AdminUser[]
}

export interface OneTimePasswordResponse {
  user: AdminUser
  one_time_password: string
}

export interface DeleteUserResponse {
  deleted: boolean
}
