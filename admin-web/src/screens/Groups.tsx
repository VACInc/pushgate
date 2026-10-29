import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import type { Group, User } from "../api";
import { Button, Card, Chip, EmptyState, Field, IconButton, Input, Modal, SearchField, SectionHeader, Select } from "../components/ui";
import { shortId } from "../utils";

export function GroupsScreen(props: {
  busy: boolean;
  groupMemberGroupId: string;
  groupMembers: User[];
  groups: Group[];
  onAddGroupUser: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onCreateGroup: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onDelete: (group: Group) => void;
  onLoadGroupMembers: (groupId: string) => Promise<boolean>;
  onRemoveGroupMember: (user: User) => void;
  onSave: (group: Group, changes: Partial<Pick<Group, "name" | "description">>) => Promise<boolean>;
  users: User[];
}) {
  const [createOpen, setCreateOpen] = useState(false);
  const [memberOpen, setMemberOpen] = useState(false);
  const [editingGroupId, setEditingGroupId] = useState("");
  const [selectedGroupId, setSelectedGroupId] = useState(props.groupMemberGroupId);
  const [query, setQuery] = useState("");
  const selectedGroup = props.groups.find((group) => group.id === props.groupMemberGroupId);
  const editingGroup = props.groups.find((group) => group.id === editingGroupId) ?? null;
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return props.groups;
    return props.groups.filter((group) => [group.name, group.description, group.id].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [props.groups, query]);

  useEffect(() => setSelectedGroupId(props.groupMemberGroupId), [props.groupMemberGroupId]);
  useEffect(() => {
    if (editingGroupId && !editingGroup) setEditingGroupId("");
  }, [editingGroup, editingGroupId]);

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreateGroup(event)) setCreateOpen(false);
  }

  async function submitMember(event: FormEvent<HTMLFormElement>) {
    if (await props.onAddGroupUser(event)) setMemberOpen(false);
  }

  return (
    <div className="screen-stack">
      <SectionHeader
        actions={
          <>
            <Button icon="plus" onClick={() => setCreateOpen(true)} variant="secondary">New group</Button>
            <Button icon="users" onClick={() => setMemberOpen(true)}>Add member</Button>
          </>
        }
        description="Organize users and inspect group membership."
        eyebrow="Directory"
        title="Groups"
      />

      <div className="split-grid">
        <Card>
          <div className="table-toolbar">
            <SearchField onChange={setQuery} placeholder="Search groups" value={query} />
            <Chip tone="info">{filtered.length} shown</Chip>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((group) => (
                  <GroupRow busy={props.busy} group={group} key={group.id} onDelete={props.onDelete} onLoadMembers={props.onLoadGroupMembers} onManage={() => setEditingGroupId(group.id)} />
                ))}
              </tbody>
            </table>
          </div>
          {!filtered.length && <EmptyState description="Create groups to manage membership for policy targeting." title="No groups found" />}
        </Card>

        <Card>
          <SectionHeader description={selectedGroup ? `Members of ${selectedGroup.name}` : "Select a group to load its members."} title="Group members" />
          <form className="inline-form" onSubmit={(event) => { event.preventDefault(); void props.onLoadGroupMembers(selectedGroupId); }}>
            <Select onChange={(event) => setSelectedGroupId(event.target.value)} required value={selectedGroupId}>
              <option disabled value="">Select group</option>
              {props.groups.map((group) => (
                <option key={group.id} value={group.id}>{group.name}</option>
              ))}
            </Select>
            <Button disabled={props.busy || !selectedGroupId} type="submit" variant="secondary">Load</Button>
          </form>
          <div className="compact-list">
            {props.groupMembers.map((user) => (
              <article key={user.id}>
                <div>
                  <strong>{user.username}</strong>
                  <span>{user.display_name || <span className="mono">{shortId(user.id)}</span>}</span>
                </div>
                <Button disabled={props.busy} onClick={() => props.onRemoveGroupMember(user)} size="sm" variant="secondary">Remove</Button>
              </article>
            ))}
            {!props.groupMembers.length && <EmptyState description="Loaded members will appear here." title="No members loaded" />}
          </div>
        </Card>
      </div>

      <CreateGroupModal busy={props.busy} onClose={() => setCreateOpen(false)} onSubmit={submitCreate} open={createOpen} />
      <AddMemberModal busy={props.busy} groups={props.groups} onClose={() => setMemberOpen(false)} onSubmit={submitMember} open={memberOpen} users={props.users} />
      <ManageGroupModal busy={props.busy} group={editingGroup} onClose={() => setEditingGroupId("")} onSave={props.onSave} />
    </div>
  );
}

function GroupRow(props: {
  busy: boolean;
  group: Group;
  onDelete: (group: Group) => void;
  onLoadMembers: (groupId: string) => Promise<boolean>;
  onManage: () => void;
}) {
  return (
    <tr>
      <td>
        <div className="entity-cell">
          <strong>{props.group.name}</strong>
          <span className="mono">{shortId(props.group.id)}</span>
        </div>
      </td>
      <td>{props.group.description || <span className="muted-copy">No description</span>}</td>
      <td>
        <div className="row-actions">
          <Button disabled={props.busy} onClick={() => void props.onLoadMembers(props.group.id)} size="sm" variant="secondary">Members</Button>
          <Button disabled={props.busy} onClick={props.onManage} size="sm" variant="secondary">Manage</Button>
          <IconButton disabled={props.busy} icon="trash" label="Delete group" onClick={() => props.onDelete(props.group)} size="sm" variant="ghost" />
        </div>
      </td>
    </tr>
  );
}

function ManageGroupModal(props: { busy: boolean; group: Group | null; onClose: () => void; onSave: (group: Group, changes: Partial<Pick<Group, "name" | "description">>) => Promise<boolean> }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  useEffect(() => {
    setName(props.group?.name ?? "");
    setDescription(props.group?.description ?? "");
  }, [props.group]);

  const changed = props.group ? name !== props.group.name || description !== (props.group.description ?? "") : false;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (props.group && await props.onSave(props.group, { name: name.trim(), description: description.trim() })) props.onClose();
  }

  return (
    <Modal description={props.group ? props.group.id : ""} onClose={props.onClose} open={Boolean(props.group)} title={props.group?.name ?? "Manage group"}>
      <form className="form-stack" onSubmit={submit}>
        <Field label="Name"><Input onChange={(event) => setName(event.target.value)} value={name} /></Field>
        <Field label="Description"><Input onChange={(event) => setDescription(event.target.value)} value={description} /></Field>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy || !changed || !name.trim()} type="submit">Save group</Button>
        </div>
      </form>
    </Modal>
  );
}

function CreateGroupModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean }) {
  return (
    <Modal description="Groups can be used by policies and member review workflows." onClose={props.onClose} open={props.open} title="New group">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <Field label="Name"><Input name="name" required /></Field>
        <Field label="Description"><Input name="description" /></Field>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy} icon="plus" type="submit">Create group</Button>
        </div>
      </form>
    </Modal>
  );
}

function AddMemberModal(props: { busy: boolean; groups: Group[]; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean; users: User[] }) {
  return (
    <Modal description="Add an existing user to a group." onClose={props.onClose} open={props.open} title="Add group member">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <Field label="Group">
          <Select defaultValue="" name="group_id" required>
            <option disabled value="">Select group</option>
            {props.groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
          </Select>
        </Field>
        <Field label="User">
          <Select defaultValue="" name="user_id" required>
            <option disabled value="">Select user</option>
            {props.users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
          </Select>
        </Field>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy} icon="plus" type="submit">Add member</Button>
        </div>
      </form>
    </Modal>
  );
}
