import { db } from '@/lib/db'
import { NextRequest, NextResponse } from 'next/server'
import { UserRole } from '@prisma/client'
import { getSession } from '@/lib/auth'
import { logActivity } from '@/lib/activity-logger'

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getSession(request)
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id } = await params

    // Agents and Students can only view their own user profile
    if (
      (session.userRole === UserRole.SALES_AGENT || session.userRole === UserRole.STUDENT) &&
      session.userId !== id
    ) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const user = await db.user.findUnique({
      where: { id },
      omit: { passwordHash: true },
      include: {
        assignedLeads: {
          include: {
            target_course: { select: { id: true, title: true } },
          },
        },
        interactions: {
          include: {
            lead: { select: { id: true, first_name: true, last_name: true } },
          },
          orderBy: { createdAt: 'desc' },
        },
        enrollments: {
          include: {
            course: { select: { id: true, title: true } },
          },
        },
        _count: {
          select: {
            assignedLeads: true,
            interactions: true,
            enrollments: true,
          },
        },
      },
    })

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }

    // Sales Managers and Dept Managers cannot view profiles in other departments (hierarchy/department isolation)
    if (session.userRole === UserRole.SALES_MANAGER || session.userRole === UserRole.DEPT_MANAGER) {
      const userProfile = await db.user.findUnique({ where: { id: session.userId }, select: { department: true } })
      if (userProfile?.department && user.department !== userProfile.department) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }

      if (session.userRole === UserRole.SALES_MANAGER) {
        if (user.role === UserRole.ADMIN || (user.role === UserRole.SALES_MANAGER && user.id !== session.userId)) {
          return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
        }
      }
    }

    return NextResponse.json(user)
  } catch (error) {
    console.error('User GET error:', error)
    return NextResponse.json(
      { error: 'Failed to fetch user' },
      { status: 500 }
    )
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getSession(request)
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id } = await params
    const body = await request.json()
    const { first_name, last_name, phone_number, role, is_active, department, personal_notes, admin_notes } = body

    // Agent/Student can only update themselves — checked before the existence
    // lookup below, so a low-privileged caller can't use 404-vs-403 to probe
    // whether an arbitrary user ID exists.
    if ((session.userRole === UserRole.SALES_AGENT || session.userRole === UserRole.STUDENT) && session.userId !== id) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Check user exists
    const existing = await db.user.findUnique({ where: { id } })
    if (!existing) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }

    // Validate role update: only Admins can set or change user roles
    if (session.userRole !== UserRole.ADMIN && role !== undefined && role !== existing.role) {
      return NextResponse.json({ error: 'Only admins can set or change user roles' }, { status: 403 })
    }

    // Agent/Student cannot change their own role or is_active status
    if (session.userRole === UserRole.SALES_AGENT || session.userRole === UserRole.STUDENT) {
      if (is_active !== undefined && is_active !== existing.is_active) {
        return NextResponse.json({ error: 'Cannot change your own active status' }, { status: 403 })
      }
    }

    // Department filtering for managers
    const userProfile = await db.user.findUnique({ where: { id: session.userId }, select: { department: true } })
    if (session.userRole === UserRole.SALES_MANAGER || session.userRole === UserRole.DEPT_MANAGER) {
      if (userProfile?.department) {
        if (existing.role === UserRole.STUDENT) {
          const isEnrolled = await db.enrollment.findFirst({
            where: {
              student_id: existing.id,
              course: { department: userProfile.department }
            }
          })
          if (!isEnrolled) {
            return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
          }
        } else {
          if (existing.department !== userProfile.department) {
            return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
          }
        }
      }

      // Sales Manager restrictions
      if (session.userRole === UserRole.SALES_MANAGER) {
        // Cannot modify Admin profiles or other Managers
        if (existing.role === UserRole.ADMIN || (existing.role === UserRole.SALES_MANAGER && existing.id !== session.userId)) {
          return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
        }
      }
    }

    // Validate that Sales Agent has a department
    const targetRole = role !== undefined ? role : existing.role
    const targetDept = department !== undefined ? department : existing.department
    if (targetRole === UserRole.SALES_AGENT && !targetDept) {
      return NextResponse.json({ error: 'Department is required for Sales Agents' }, { status: 400 })
    }

    // Check phone number uniqueness if changing
    if (phone_number && phone_number !== existing.phone_number) {
      const duplicate = await db.user.findUnique({
        where: { phone_number },
      })
      if (duplicate) {
        return NextResponse.json(
          { error: 'A user with this phone number already exists' },
          { status: 409 }
        )
      }
    }

    // personal_notes is private — only the account owner can change it
    if (personal_notes !== undefined && session.userId !== id) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // admin_notes is management-only
    if (
      admin_notes !== undefined &&
      session.userRole !== UserRole.ADMIN &&
      session.userRole !== UserRole.DEPT_MANAGER
    ) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const user = await db.user.update({
      where: { id },
      data: {
        ...(first_name !== undefined && { first_name }),
        ...(last_name !== undefined && { last_name }),
        ...(phone_number !== undefined && { phone_number }),
        ...(role !== undefined && { role }),
        ...(is_active !== undefined && { is_active }),
        ...(department !== undefined && { department }),
        ...(personal_notes !== undefined && { personal_notes }),
        ...(admin_notes !== undefined && { admin_notes }),
      },
    })

    await logActivity(
      request,
      'UPDATE_USER',
      `Updated user details for "${user.first_name} ${user.last_name}" (Role: ${user.role})`
    )

    return NextResponse.json(user)
  } catch (error) {
    console.error('User PUT error:', error)
    return NextResponse.json(
      { error: 'Failed to update user' },
      { status: 500 }
    )
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getSession(request)
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id } = await params

    // Only Admins and Sales Managers / Dept Managers can delete users
    if (
      session.userRole !== UserRole.ADMIN &&
      session.userRole !== UserRole.SALES_MANAGER &&
      session.userRole !== UserRole.DEPT_MANAGER
    ) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Check user exists
    const existing = await db.user.findUnique({ where: { id } })
    if (!existing) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }

    // Department filtering for managers
    const userProfile = await db.user.findUnique({ where: { id: session.userId }, select: { department: true } })
    if (session.userRole === UserRole.SALES_MANAGER || session.userRole === UserRole.DEPT_MANAGER) {
      if (userProfile?.department) {
        if (existing.role === UserRole.STUDENT) {
          const isEnrolled = await db.enrollment.findFirst({
            where: {
              student_id: existing.id,
              course: { department: userProfile.department }
            }
          })
          if (!isEnrolled) {
            return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
          }
        } else {
          if (existing.department !== userProfile.department) {
            return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
          }
        }
      }

      if (session.userRole === UserRole.SALES_MANAGER) {
        if (existing.role === UserRole.ADMIN || existing.role === UserRole.SALES_MANAGER) {
          return NextResponse.json({ error: 'Managers cannot delete Admin or Manager accounts' }, { status: 403 })
        }
      }
    }

    if (existing.id === session.userId) {
      return NextResponse.json({ error: 'You cannot delete your own account' }, { status: 400 })
    }

    // Hard delete: clear nullable lead ownership first, then remove every
    // user-owned record before deleting the user itself. This keeps the
    // operation atomic and avoids orphaned records/foreign-key failures.
    await db.$transaction(async (tx) => {
      await tx.lead.updateMany({
        where: { assigned_to_id: id },
        data: { assigned_to_id: null },
      })
      await tx.lead.updateMany({
        where: { referred_by_id: id },
        data: { referred_by_id: null },
      })
      await tx.activityLog.deleteMany({ where: { user_id: id } })
      await tx.interaction.deleteMany({ where: { agent_id: id } })
      await tx.enrollment.deleteMany({ where: { student_id: id } })
      await tx.ticket.deleteMany({ where: { student_id: id } })
      await tx.task.deleteMany({ where: { agent_id: id } })
      await tx.commission.deleteMany({ where: { referrer_id: id } })
      await tx.purchaseRequest.deleteMany({ where: { requester_id: id } })
      await tx.session.deleteMany({ where: { userId: id } })
      await tx.account.deleteMany({ where: { userId: id } })
      await tx.passwordResetToken.deleteMany({ where: { userId: id } })
      await tx.user.delete({ where: { id } })
    })

    await logActivity(
      request,
      'DELETE_USER',
      `Permanently deleted user "${existing.first_name} ${existing.last_name}" (Role: ${existing.role})`
    )

    return NextResponse.json({ success: true, id })
  } catch (error) {
    console.error('User DELETE error:', error)
    return NextResponse.json(
      { error: 'Failed to delete user' },
      { status: 500 }
    )
  }
}
