import { useState } from 'react';
import { ApiClient } from '../../api/client';
import { CollectionStatus } from '../status/CollectionStatus';
import { EventList } from './EventList';

export function EventsPage({ client, location }: { client: ApiClient; location: string }) {
 const [revision, setRevision] = useState(0);
 const [statusLoading, setStatusLoading] = useState(true);
 return <EventList key={location} client={client} refreshing={statusLoading}
  onRefresh={() => setRevision(n => n + 1)}
  summary={<CollectionStatus client={client} refreshRevision={revision} onLoadingChange={setStatusLoading} />} />;
}
